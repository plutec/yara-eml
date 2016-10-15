/*
Copyright (c) 2016. Antonio Sanchez (asanchez@plutec.net). All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/modules.h>

#define MODULE_NAME eml

#define UNKNOWN 1
#define X_STORE_INFO 2
#define RECEIVED 3
#define AUTHENTICATION_RESULTS 4
#define DELIVERED_TO 5

struct HeaderField {
  int field_type;
  char *value;
} header_field;



begin_declarations;
  //declare_function("x_received");
  declare_string_array("x_received");
  declare_integer("number_of_x_received");

  declare_string_array("x_store_info");
  declare_integer("number_of_x_store_info");
  /*declare_function("mime_type", "", "s", magic_mime_type);
  declare_function("type", "", "s", magic_type);*/

end_declarations;


int module_initialize(
    YR_MODULE* module)
{

  return ERROR_SUCCESS;
}


int module_finalize(
    YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

/* Categorize the header type */
struct HeaderField* header_type(char* line) {
  int i = 0;
  struct HeaderField *to_ret;
  to_ret = (struct HeaderField*)malloc(sizeof(struct HeaderField));
  size_t size = strlen(line);
  while(line[i] != ':' || i == size) {
    ++i;
  }
  if (i == size) {
    printf("Ha llegado al final y no lo encuentra, fuera");
  }
  //printf("Colon in %d\n", i);
  char *key ;
  key = (char*)malloc((i+1)*sizeof(char));
  memcpy(key, line, i);
  key[i] = '\0';
  printf("Key: %s\n", key);
  if (strcasecmp(key, "x-store-info") == 0) {
    to_ret->field_type = X_STORE_INFO;
    to_ret->value = (char*)malloc((strlen(line)-i+1)*sizeof(char));
    memcpy(to_ret->value, line+i, strlen(line)-i);
    printf("Header value %s\n", to_ret->value);
    //to_ret = X_STORE_INFO;
  } else if (!strcasecmp(key, "received")) {
    to_ret->field_type = RECEIVED;
    to_ret->value = (char*)malloc((strlen(line)-i+1)*sizeof(char));
    memcpy(to_ret->value, line+i, strlen(line)-i);
    //to_ret = X_STORE_INFO;
  }  

  else if (strcasecmp(key, "Authentication-Results") == 0) { 
    //to_ret = AUTHENTICATION_RESULTS;
    to_ret->field_type = AUTHENTICATION_RESULTS;
    to_ret->value = (char*)malloc((strlen(line)-i+1)*sizeof(char));
    memcpy(to_ret->value, line+i, strlen(line)-i);
    printf("Header value %s\n", to_ret->value);
  } else {
    free(to_ret);
    to_ret = NULL;
  }
  free(key);
  return to_ret;
}

struct HeaderIt {
   char *data;
   size_t size;
   char *ptr;
   int end;
};  

struct HeaderIt* header_init(void* data, size_t size) {
  struct HeaderIt *to_ret;
  to_ret = (struct HeaderIt*)malloc(sizeof(struct HeaderIt));
  to_ret->size = size;
  to_ret->data = (char*)data;
  to_ret->ptr = data; 
  to_ret->end = 0;
  return to_ret;
}

int is_endline(char ptr1, char ptr2) {
  if (ptr1 == '\r' && ptr2 == '\n')
    return 1;
  if (ptr1 == '\n')
    return 1;
  return 0;
}

//struct HeaderIt header_begin(Value a[]){ return &a[0];}
//struct HeaderIt header_end(Value a[], int n){ return &a[n];}
char* header_next(struct HeaderIt *it) { 


  char *to_ret;
  int i = 0;

  if (it->end == 1) {
    return NULL;
  }

  int end_header = 0;
  while (!end_header) {
    ++i;
    //if (it->ptr[i] == '\n') {
    if (is_endline(it->ptr[i], it->ptr[i+1])) {
        //if (it->ptr[i+1] != '\t' && it->ptr[i+1] != ' ') {
        if (it->ptr[i+2] != '\t' && it->ptr[i+3] != ' ') {
           end_header = 1;
           //if (it->ptr[i+1] == '\r' && it->ptr[i+2] == '\n') {
           if (is_endline(it->ptr[i+2], it->ptr[i+3])) {
              it->end = 1;
              printf("FIN DE TODOS LOS HEADERS\n");
           }
           printf("Fin de header\n");
        }
    }
  }
  if (i == 0) { return NULL; }

  //Alloc memory for this block
  to_ret = (char*)malloc((i+1)*sizeof(char));
  memcpy (to_ret, it->ptr, i);
  to_ret[i] = '\0';

  //Sometimes the lines finished with \n and another times with \r\n
  //The +1 or +2 is to "remove" the \n or \r\n previous to the next header
  it->ptr += i; 
  if (it->ptr[0] == '\r') {
    it->ptr += 2; 
  } else if (it->ptr[0] == '\n') {
    it->ptr += 1;
  }
  
  return to_ret;
  //return ++i;


}
void header_destroy(struct HeaderIt **header) {
 //TODO memleak
}


void debug_print_header(struct HeaderField *a) {
    printf("Type %d, value %s\n", a->field_type, a->value);
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  uint8_t* block_data = NULL;
  char *a;
  struct HeaderIt *head_iterator;
  struct HeaderField *b;
  

  foreach_memory_block(iterator, block)
  {
    block_data = block->fetch_data(block);
    head_iterator = header_init(block_data, block->size);
    printf("Iterator iniciated\n");
    a = header_next(head_iterator);
    printf("First header catched\n");
    while(a) {
      //counter += strlen(a) +1;
      printf("VAMOS: %s\n", a);
      b = header_type(a);
      if (b!=NULL) {
        debug_print_header(b);
      }
      

      free(a);
      a = header_next(head_iterator);
    }

    header_destroy(&head_iterator);
    set_string("manolito", module_object, "x_received[0]");
    set_integer(1, module_object, "number_of_x_received");
  }
  //set_string("manolito", get_object(module_object, "x_received"), "x_received[1]");
  //set_string("manolito", get_object(module_object, "x_received"), "x_received[2]");
  //network_obj = get_object(module_object, "network");

  return ERROR_SUCCESS;
}


int module_unload(
    YR_OBJECT* module)
{
  return ERROR_SUCCESS;
}
