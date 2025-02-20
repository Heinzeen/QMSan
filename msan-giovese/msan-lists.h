
#include <stdlib.h>
#include <unistd.h>
#include "stdint.h"


typedef struct node{
    struct node *next;
    uintptr_t start;
    uintptr_t end;
}node;

typedef struct{
    node* start;
    node* last;
} mmap_list;

mmap_list* list = NULL;

#define MAX2(x, y) (((x) > (y)) ? (x) : (y))
#define MIN2(x, y) (((x) < (y)) ? (x) : (y))


static void create_mmap_list(){
    list = (mmap_list*) malloc(sizeof(mmap_list));

    list->start = NULL;
    list->last = NULL;

}

/*
static void delete_mmap_list(mmap_list* list){

    //iterate and deallocate

}*/

// static void add_item_last_mmap_list(uintptr_t start, uintptr_t end){

//     if(list->start == NULL){
//         list->start = (node*) malloc(sizeof(node));
//         list->last = list->start;

//         list->start->start = start;
//         list->start->end = end;
//         list->start->next = NULL;
//         return;
//     }

//     node* new_node = (node*) malloc(sizeof(node));
//     new_node->next = NULL;
//     new_node->start = start;
//     new_node->end = end;

//     node* prev = list->last;
//     prev->next = new_node;
//     list->last = new_node;

// }

static void manage_new_mmap_list(uintptr_t start, uintptr_t end){

    if(!list)
        create_mmap_list();

    node* item = list->start;

    //first item?
    if(!item){
        list->start = (node*) malloc(sizeof(node));
        list->last = list->start;

        list->start->start = start;
        list->start->end = end;
        list->start->next = NULL;
        return;
    }

    node* prev = NULL;

    while(item){
        if(start < item->start){            
            break;            
        }
        prev = item;
        item = item->next;
    }
    //FIXME: untill we manage munmount it is possible to have overlappings
    if(item && item->start == start)
        item->end == MAX2(end, item->end);

    //create a new item
    node* new_node = (node*) malloc(sizeof(node));
    new_node->next = item;
    new_node->start = start;
    new_node->end = end;

    //update the previous item
    if(!prev)
        list->start = new_node;
    else
        prev->next = new_node;
    
    //did we traverse the whole list?
    if(!item)
        list->last = new_node;
}


static void remove_mmap_list(uintptr_t start, uint64_t len){

    if(!list)
        return;

    node* item = list->start;

    if(!item)
        return;

    node* prev = NULL;

    while(item){
        if(start == item->start){            
            break;            
        }
        prev = item;
        item = item->next;
    }

    //not found!
    if(!item)
        return;

    if(prev)
        prev->next = item->next;
    else
        list->start = item->next;
    
    if(!item->next)
        list->last = prev;

    free(item);
}

//remove an item if we detect malloc allocating inside it
static void check_mmap_list(uintptr_t ptr){

    if(!list)
        return;

    node* item = list->start;

    if(!item)
        return;

    node* prev = NULL;

    while(item){
        if(ptr >= item->start && ptr < item->end){            
            break;            
        }
        prev = item;
        item = item->next;
    }

    //not found!
    if(!item)
        return;

    if(prev)
        prev->next = item->next;
    else
        list->start = item->next;
    
    if(!item->next)
        list->last = prev;

    free(item);
}

static int check_addr_mmap_list(uintptr_t addr){

    if(!list)
        return 0;

    node* item = list->start;

    while(item){
        if(item->start <= addr && item->end >= addr)
            return 1;
        item = (node*) item->next;
    }

    return 0;
}

#ifdef MSAN_DEBUG_MMAP_INFO
static void print_mmap_list(){

    if(!list)
        return;

    node* item = list->start;

    while(item){
        fprintf(stderr, "[mmap_list] new block from %lx to %lx\n", item->start, item->end);
        item = (node*) item->next;
    }

}
#endif

