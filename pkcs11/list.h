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

#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

typedef void (*FreeItemFn)(void *);

typedef bool (*CompareItemFn)(void *, void *);

typedef void (*IteratorFn)(void *);

typedef struct ListItem ListItem;

struct ListItem {
  void *data;
  ListItem *next;
};

typedef struct {
  int length;
  int item_size;
  ListItem *head;
  ListItem *tail;
  FreeItemFn free_item_fn;
} List;

void list_create(List *list, int item_size, FreeItemFn free_item_fn);
void list_destroy(List *list);

bool list_prepend(List *list, void *item);
bool list_append(List *list, void *item);

ListItem *list_get(List *list, void *data, CompareItemFn compare_item_fn);
void list_delete(List *list, ListItem *item);

void list_iterate(List *list, IteratorFn iterator_fn);

#endif
