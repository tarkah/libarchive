/*-
 * Copyright (c) 2011 Michihiro NAKAJIMA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdio.h>
#ifdef HAVE_STONE_H
#include <stone.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_entry_private.h"
#include "archive_private.h"
#include "archive_rb.h"
#include "archive_read_private.h"

#if (!defined(HAVE_STONE_H) || !defined(HAVE_LIBSTONE))

int archive_read_support_format_stone(struct archive *_a) {
  struct archive_read *a = (struct archive_read *)_a;
  archive_check_magic(_a, ARCHIVE_READ_MAGIC, ARCHIVE_STATE_NEW,
                      "archive_read_support_format_stone");

  archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                    "stone format not supported on this platform");
  return (ARCHIVE_WARN);
}

#else /* Support stone format */

#define minimum(a, b) (a < b ? a : b)

static int archive_read_format_stone_bid(struct archive_read *, int);
static int archive_read_format_stone_cleanup(struct archive_read *);
static int archive_read_format_stone_read_header(struct archive_read *,
                                                 struct archive_entry *);
static int archive_read_format_stone_read_data(struct archive_read *,
                                               const void **, size_t *,
                                               int64_t *);
static int archive_read_format_stone_read_data_skip(struct archive_read *);
static signed int cmp_index_nodes(const struct archive_rb_node *,
                                  const struct archive_rb_node *);
static signed int cmp_index_keys(const struct archive_rb_node *, const void *);
static signed int cmp_file_nodes(const struct archive_rb_node *,
                                 const struct archive_rb_node *);
static char *stone_string_to_cstring(const StoneString *);

size_t read_shim(void *, char *, size_t);
int64_t seek_shim(void *, int64_t, StoneSeekFrom);

struct _payload {
  StonePayload *ptr;
  StonePayloadHeader header;
};

struct _index {
  struct archive_rb_node node;
  StonePayloadIndexRecord record;
  char *matched_path;
};

struct _layout {
  StonePayloadLayoutRecord record;
};

struct _file {
  struct archive_rb_node node;
  const struct _layout *layout;
  struct _index *index;
  mode_t type;
  char *path;
  char *link;
  char *hardlink;
  size_t offset;
  uint64_t size;
};

struct _stone {
  StoneHeaderV1 header;
  StoneReader *reader;
  StonePayloadContentReader *content_reader;
  struct _payload *payloads;
  struct _index *indexes;
  struct _layout *layouts;
  struct _payload *content;
  struct _file *files;
  struct archive_rb_tree index_tree;
  struct archive_rb_tree file_tree;
  int nindex;
  int nlayout;
  // int nfiles;
  struct _file *file;
  char outbuf[2048];
};

static signed int cmp_index_nodes(const struct archive_rb_node *n1,
                                  const struct archive_rb_node *n2) {
  const struct _index *e1 = (const struct _index *)n1;
  const struct _index *e2 = (const struct _index *)n2;

  return memcmp(e2->record.digest, e1->record.digest, 16);
}

static signed int cmp_index_keys(const struct archive_rb_node *n,
                                 const void *_key) {
  const struct _index *e = (const struct _index *)n;
  const uint8_t *key = (const uint8_t *)_key;

  return memcmp(key, &e->record.digest, 16);
}

static signed int cmp_file_nodes(const struct archive_rb_node *n1,
                                 const struct archive_rb_node *n2) {
  const struct _file *e1 = (const struct _file *)n1;
  const struct _file *e2 = (const struct _file *)n2;

  if (e1->index == NULL && e2->index != NULL) {
    return -1;
  } else if (e1->index != NULL && e2->index == NULL) {
    return 1;
  } else if (e1->index == NULL && e2->index == NULL) {
    return strcmp(e2->path, e1->path);
  } else {
    return (e2->index->record.start > e1->index->record.start) -
           (e2->index->record.start < e1->index->record.start);
  }
}

// static signed int cmp_file_keys(const struct archive_rb_node *n,
//                                 const void *_key) {
//   const struct _file *e = (const struct _file *)n;
//   const uint64_t *key = (const uint64_t *)_key;

//   return (*key > e->index->record.start) - (*key < e->index->record.start);
// }

struct archive_rb_tree_ops rb_index_ops = {&cmp_index_nodes, &cmp_index_keys};
struct archive_rb_tree_ops rb_file_ops = {&cmp_file_nodes,
                                          .rbto_compare_key = NULL};

StoneReadVTable stone_read_vtable = {
    .read = read_shim,
    .seek = seek_shim,
};

int archive_read_support_format_stone(struct archive *_a) {
  struct archive_read *a = (struct archive_read *)_a;
  struct _stone *stone;
  int r;

  archive_check_magic(_a, ARCHIVE_READ_MAGIC, ARCHIVE_STATE_NEW,
                      "archive_read_support_format_stone");

  stone = calloc(1, sizeof(*stone));

  if (stone == NULL) {
    archive_set_error(&a->archive, ENOMEM, "Can't allocate stone data");
    return (ARCHIVE_FATAL);
  }

  r = __archive_read_register_format(
      a, stone, "stone", archive_read_format_stone_bid, NULL,
      archive_read_format_stone_read_header,
      archive_read_format_stone_read_data,
      archive_read_format_stone_read_data_skip, NULL,
      archive_read_format_stone_cleanup, NULL, NULL);

  if (r != ARCHIVE_OK)
    free(stone);

  return (ARCHIVE_OK);
}

static int archive_read_format_stone_bid(struct archive_read *a, int best_bid) {
  struct _stone *stone;
  StoneHeaderVersion version;

  stone = (struct _stone *)(a->format->data);

  /* If there's already a better bid than we can ever
     make, don't bother testing. */
  if (best_bid > STONE_HEADER_SIZE) {
    return -1;
  }

  if (stone_read(a, stone_read_vtable, &stone->reader, &version) < 0) {
    return 0;
  }

  if (version != STONE_HEADER_VERSION_V1) {
    return 0;
  }

  if (stone_reader_header_v1(stone->reader, &stone->header) < 0) {
    return 0;
  }

  if (stone->header.file_type != STONE_HEADER_V1_FILE_TYPE_BINARY) {
    return 0;
  }

  return STONE_HEADER_SIZE;
}

static int archive_read_format_stone_read_header(struct archive_read *a,
                                                 struct archive_entry *entry) {
  struct _stone *stone;

  (void)entry; /* UNUSED */

  stone = (struct _stone *)(a->format->data);

  a->archive.archive_format = ARCHIVE_FORMAT_STONE;
  if (a->archive.archive_format_name == NULL)
    a->archive.archive_format_name = "stone";

  if (stone->payloads == 0) {
    __archive_rb_tree_init(&stone->index_tree, &rb_index_ops);
    __archive_rb_tree_init(&stone->file_tree, &rb_file_ops);

    if (a->filter->position != STONE_HEADER_SIZE) {
      __archive_read_seek(a, STONE_HEADER_SIZE, 0);
    }

    stone->payloads =
        calloc(stone->header.num_payloads, sizeof(struct _payload));
    if (stone->payloads == NULL) {
      archive_set_error(&a->archive, ENOMEM,
                        "Can't allocate memory for payloads");
      return (ARCHIVE_FATAL);
    }

    for (int p = 0; p < stone->header.num_payloads; p++) {
      struct _payload *payload = &stone->payloads[p];

      stone_reader_next_payload(stone->reader, &payload->ptr);
      stone_payload_header(payload->ptr, &payload->header);

      switch (payload->header.kind) {
      case STONE_PAYLOAD_KIND_INDEX: {
        struct _index *index;

        stone->indexes = realloc(
            stone->indexes, sizeof(*stone->indexes) *
                                (stone->nindex + payload->header.num_records));
        if (stone->indexes == NULL) {
          archive_set_error(&a->archive, ENOMEM,
                            "Can't allocate memory for index records");
          return (ARCHIVE_FATAL);
        }

        for (int r = 0; r < (int)payload->header.num_records; r++) {
          index = &stone->indexes[stone->nindex + r];
          memset(index, 0, sizeof(*index));
          stone_payload_next_index_record(payload->ptr, &index->record);
          __archive_rb_tree_insert_node(&stone->index_tree, &index->node);
        }

        stone->nindex += payload->header.num_records;
        break;
      }
      case STONE_PAYLOAD_KIND_LAYOUT: {
        struct _layout *layout;

        stone->layouts = realloc(
            stone->layouts, sizeof(StonePayloadLayoutRecord) *
                                (stone->nlayout + payload->header.num_records));

        if (stone->layouts == NULL) {
          archive_set_error(&a->archive, ENOMEM,
                            "Can't allocate memory for layout records");
          return (ARCHIVE_FATAL);
        }

        for (int r = 0; r < (int)payload->header.num_records; r++) {
          layout = &stone->layouts[stone->nlayout + r];
          memset(layout, 0, sizeof(*layout));
          stone_payload_next_layout_record(payload->ptr, &layout->record);
        }

        stone->nlayout += payload->header.num_records;
        break;
      }
      case STONE_PAYLOAD_KIND_CONTENT: {
        stone->content = payload;
      }
      default: {
        break;
      }
      }
    }

    if (stone->nlayout == 0 || stone->content == NULL) {
      return (ARCHIVE_EOF);
    }

    stone->files = calloc(stone->nlayout, sizeof(*stone->files));

    for (int l = 0; l < stone->nlayout; l++) {
      struct _file *file;
      const struct _layout *layout = &stone->layouts[l];

      file = &stone->files[l];
      file->layout = layout;

      switch (layout->record.file_type) {
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_REGULAR: {
        file->type = AE_IFREG;
        file->path = stone_string_to_cstring(
            &file->layout->record.file_payload.regular.name);
        break;
      }
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_SYMLINK: {
        file->type = AE_IFLNK;
        file->path = stone_string_to_cstring(
            &file->layout->record.file_payload.symlink.target);
        file->link = stone_string_to_cstring(
            &file->layout->record.file_payload.symlink.source);

        if (file->link == NULL) {
          archive_set_error(&a->archive, ENOMEM,
                            "Can't allocate memory for link name");
          return (ARCHIVE_FATAL);
        }

        break;
      }
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_DIRECTORY: {
        file->type = AE_IFDIR;
        file->path = stone_string_to_cstring(
            &file->layout->record.file_payload.directory);
        break;
      }
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_CHARACTER_DEVICE: {
        file->type = AE_IFCHR;
        file->path = stone_string_to_cstring(
            &file->layout->record.file_payload.character_device);
        break;
      }
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_BLOCK_DEVICE: {
        file->type = AE_IFBLK;
        file->path = stone_string_to_cstring(
            &file->layout->record.file_payload.block_device);
        break;
      }
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_FIFO: {
        file->type = AE_IFIFO;
        file->path =
            stone_string_to_cstring(&file->layout->record.file_payload.fifo);
        break;
      }
      case STONE_PAYLOAD_LAYOUT_FILE_TYPE_SOCKET: {
        file->type = AE_IFSOCK;
        file->path =
            stone_string_to_cstring(&file->layout->record.file_payload.socket);
        break;
      }
      default: {
        break;
      }
      }

      if (file->path == NULL) {
        archive_set_error(&a->archive, ENOMEM,
                          "Can't allocate memory for file name");
        return (ARCHIVE_FATAL);
      }

      if (layout->record.file_type == STONE_PAYLOAD_LAYOUT_FILE_TYPE_REGULAR) {
        struct _index *index = (struct _index *)__archive_rb_tree_find_node(
            &stone->index_tree, &layout->record.file_payload.regular.hash);

        file->size = index->record.end - index->record.start;

        if (index->matched_path == NULL) {
          index->matched_path = file->path;
          file->index = index;
        } else {
          file->hardlink = index->matched_path;
        }
      }

      __archive_rb_tree_insert_node(&stone->file_tree, &file->node);
    }

    stone->file = (struct _file *)ARCHIVE_RB_TREE_MIN(&stone->file_tree);

    stone_reader_read_content_payload(stone->reader, stone->content->ptr,
                                      &stone->content_reader);
  } else {
    stone->file = (struct _file *)ARCHIVE_RB_TREE_NEXT(
        &stone->file_tree, (struct archive_rb_node *)stone->file);
  }

  if (stone->file != NULL) {
    const struct _file *file = stone->file;

    archive_entry_set_pathname_utf8(entry, file->path);
    archive_entry_set_filetype(entry, file->type);

    if (file->link != NULL) {
      archive_entry_set_symlink_utf8(entry, file->link);
    } else if (file->hardlink != NULL) {
      archive_entry_set_hardlink_utf8(entry, file->hardlink);
    }

    archive_entry_set_uid(entry, file->layout->record.uid);
    archive_entry_set_gid(entry, file->layout->record.gid);
    archive_entry_set_mode(entry, file->layout->record.mode);

    if (file->size > 0) {
      archive_entry_set_size(entry, file->size);
    }

    return (ARCHIVE_OK);
  } else {
    return (ARCHIVE_EOF);
  }
}

static int archive_read_format_stone_read_data(struct archive_read *a,
                                               const void **buf, size_t *size,
                                               int64_t *offset) {
  struct _stone *stone;
  struct _file *file;

  stone = (struct _stone *)(a->format->data);
  *buf = &stone->outbuf;
  file = stone->file;

  if (file->index == NULL) {
    return (ARCHIVE_EOF);
  }

  int rem = file->size - file->offset;
  int avail = minimum(sizeof(stone->outbuf), (uint64_t)rem);

  if (rem == 0) {
    return (ARCHIVE_EOF);
  }

  *size = stone_payload_content_reader_read(stone->content_reader,
                                            (void *)&stone->outbuf, avail);

  *offset = file->offset;
  file->offset += *size;

  return (ARCHIVE_OK);
}

static int archive_read_format_stone_read_data_skip(struct archive_read *a) {
  struct _stone *stone;
  const struct _file *file;
  size_t read = 0;
  int64_t offset = 0;
  int ret;
  const void *buf;

  stone = (struct _stone *)(a->format->data);
  file = stone->file;

  if (file->index != NULL) {
    while ((ret = archive_read_format_stone_read_data(a, &buf, &read,
                                                      &offset)) == ARCHIVE_OK) {
    }
    if (ret != ARCHIVE_EOF) {
      return ret;
    }
  }

  return (ARCHIVE_OK);
}

static int archive_read_format_stone_cleanup(struct archive_read *a) {
  struct _stone *stone;

  stone = (struct _stone *)(a->format->data);

  for (int i = 0; i < stone->nlayout; i++) {
    free(stone->files[i].path);
    free(stone->files[i].link);
  }
  free(stone->files);
  free(stone->indexes);
  free(stone->layouts);
  stone_payload_content_reader_destroy(stone->content_reader);
  for (int i = 0; i < stone->header.num_payloads; i++) {
    stone_payload_destroy(stone->payloads[i].ptr);
  }
  free(stone->payloads);
  stone_reader_destroy(stone->reader);
  free(stone);

  (a->format->data) = NULL;

  return (ARCHIVE_OK);
}

size_t read_shim(void *_a, char *buf, size_t size) {
  struct archive_read *a = (struct archive_read *)_a;
  ssize_t avail = 0;
  size_t min;
  const char *p;

  if ((p = __archive_read_ahead(a, 1, &avail)) == NULL)
    return 0;

  min = minimum((size_t)avail, size);

  memcpy(buf, p, min);

  __archive_read_consume(a, min);

  return min;
}

int64_t seek_shim(void *_a, int64_t offset, StoneSeekFrom from) {
  struct archive_read *a = (struct archive_read *)_a;

  return __archive_read_seek(a, offset, from);
}

static char *stone_string_to_cstring(const StoneString *stone) {
  char *p;

  p = calloc(stone->size + 1, 1);
  if (p == NULL) {
    return (p);
  }
  memcpy(p, stone->buf, stone->size);
  return (p);
}

#endif /* Support stone format */
