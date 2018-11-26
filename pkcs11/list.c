/*
 * Copyright 2015-2018 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "list.h"

#include <stdlib.h>
#include <string.h>

#include "../common/insecure_memzero.h"

void list_create(List *list, int item_size, FreeItemFn free_item_fn) {

  list->length = 0;
  list->item_size = item_size;
  list->head = NULL;
  list->tail = NULL;
  list->free_item_fn = free_item_fn;
}

void list_destroy(List *list) {

  ListItem *current;

  while (list->head != NULL) {
    current = list->head;
    list->head = current->next;

    if (list->free_item_fn) {
      list->free_item_fn(current->data);
    }

    insecure_memzero(current->data, list->item_size);
    free(current->data);
    free(current);
  }
}

bool list_prepend(List *list, void *item) {

  ListItem *node = calloc(1, sizeof(ListItem));
  if (node == NULL) {
    return false;
  }

  node->data = calloc(1, list->item_size);

  if (node->data == NULL) {
    free(node);
    return false;
  }

  memcpy(node->data, item, list->item_size);

  node->next = list->head;
  list->head = node;

  if (list->tail == NULL) {
    list->tail = list->head;
  }

  list->length++;
  return true;
}

bool list_append(List *list, void *item) {

  ListItem *node = calloc(1, sizeof(ListItem));
  if (node == NULL) {
    return false;
  }

  node->data = calloc(1, list->item_size);
  if (node->data == NULL) {
    free(node);
    return false;
  }

  memcpy(node->data, item, list->item_size);

  if (list->length == 0) {
    list->head = node;
    list->tail = node;
  } else {
    list->tail->next = node;
    list->tail = node;
  }

  list->length++;
  return true;
}

ListItem *list_get(List *list, void *data, CompareItemFn compare_item_fn) {

  for (ListItem *item = list->head; item != NULL; item = item->next) {
    if (compare_item_fn(data, item->data) == true) {

      return item;
    }
  }

  return NULL;
}

void list_delete(List *list, ListItem *item) {

  if (item == NULL) {

    return;
  }

  if (item == list->head) {
    if (list->head == list->tail) {
      list->head = NULL;
      list->tail = NULL;
    } else {
      list->head = list->head->next;
    }

    if (list->free_item_fn) {
      list->free_item_fn(item->data);
    }
    insecure_memzero(item->data, list->item_size);
    free(item->data);
    free(item);
  } else if (item == list->tail) {
    for (ListItem *i = list->head; i != NULL; i = i->next) {
      if (i->next == list->tail) {
        list->tail = i;
        i->next = NULL;

        if (list->free_item_fn) {
          list->free_item_fn(item->data);
        }
        insecure_memzero(item->data, list->item_size);
        free(item->data);
        free(item);
      }
    }
  } else {
    if (list->free_item_fn) {
      list->free_item_fn(item->data);
    }

    ListItem *tmp = item->next;

    insecure_memzero(item->data, list->item_size);
    free(item->data);

    item->data = item->next->data;
    item->next = item->next->next;

    if (tmp == list->tail) {
      list->tail = item;
    }

    free(tmp);
  }

  list->length--;
}

void list_iterate(List *list, IteratorFn iterator_fn) {

  for (ListItem *item = list->head; item != NULL; item = item->next) {
    iterator_fn(item->data);
  }
}
