// Copyright (c) 2023 Christoffer Lerno. All rights reserved.
// Use of this source code is governed by the MIT license
// a copy of which can be found in the LICENSE_STDLIB file.
<*
 @require $defined((Key){}.hash()) : `No .hash function found on the key`
*>
module std::collections::map <Key, Value>;
import std::math;
import std::io @norecurse;

const LinkedHashMap LINKEDONHEAP = { .allocator = MAP_HEAP_ALLOCATOR };

struct LinkedEntry
{
	uint hash;
	Key key;
	Value value;
	<* For bucket chain *>
	LinkedEntry* next;
	<* Previous in insertion order *>
	LinkedEntry* before;
	<* Next in insertion order *>
	LinkedEntry* after;
}

struct LinkedHashMap (Printable)
{
	LinkedEntry*[] table;
	Allocator allocator;
	int count;
	int threshold;
	float load_factor;
	<* First inserted LinkedEntry *>
	LinkedEntry* head;
	<* Last inserted LinkedEntry *>
	LinkedEntry* tail;
}


<*
 @param [&inout] allocator : "The allocator to use"
 @require capacity > 0 : "The capacity must be 1 or higher"
 @require load_factor > 0.0 && load_factor <= 1 : "The load factor must be higher than 0 and less or equal to 1"
 @require !self.is_initialized() : "Map was already initialized"
 @require capacity <= MAXIMUM_CAPACITY : "Capacity cannot exceed maximum"
*>
fn LinkedHashMap* LinkedHashMap.init(&self, Allocator allocator, sz capacity = DEFAULT_INITIAL_CAPACITY, float load_factor = DEFAULT_LOAD_FACTOR)
{
	capacity = math::next_power_of_2(capacity);
	self.allocator = allocator;
	self.load_factor = load_factor;
	self.threshold = (int)(capacity * load_factor);
	self.table = alloc::new_array(allocator, LinkedEntry*, capacity);
	self.head = null;
	self.tail = null;
	return self;
}

<*
 @require capacity > 0 : "The capacity must be 1 or higher"
 @require load_factor > 0.0 && load_factor <= 1 : "The load factor must be higher than 0 and less or equal to 1"
 @require !self.is_initialized() : "Map was already initialized"
 @require capacity <= MAXIMUM_CAPACITY : "Capacity cannot exceed maximum"
*>
fn LinkedHashMap* LinkedHashMap.tinit(&self, sz capacity = DEFAULT_INITIAL_CAPACITY, float load_factor = DEFAULT_LOAD_FACTOR)
{
	return self.init(tmem, capacity, load_factor) @inline;
}

<*
 @param [&inout] allocator : "The allocator to use"
 @require $vaarg.$reflect(len).offset % 2 == 0 : "There must be an even number of arguments provided for keys and values"
 @require capacity > 0 : "The capacity must be 1 or higher"
 @require load_factor > 0.0 && load_factor <= 1 : "The load factor must be higher than 0 and less or equal to 1"
 @require !self.is_initialized() : "Map was already initialized"
 @require capacity <= MAXIMUM_CAPACITY : "Capacity cannot exceed maximum"
*>
macro LinkedHashMap* LinkedHashMap.init_with_key_values(&self, Allocator allocator, ..., sz capacity = DEFAULT_INITIAL_CAPACITY, float @kindof(load_factor) =bool y = { true, false, }[n] = 33