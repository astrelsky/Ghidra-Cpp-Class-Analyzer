package cppclassanalyzer.database.utils;

import ghidra.util.datastruct.LongArrayList;

public class LongStack extends LongArrayList {

	/**
	 * Removes the object at the top of this stack and returns that object as the value
	 * of this function.
	 * @return the element popped from the stack
	 */
	public long pop() {
		return remove(size() - 1);
	}

	/**
	 * Pushes an item onto the top of this stack
	 * @param item the object to push onto the stack
	 * @return the item pushed onto the stack
	 */
	public long push(long item) {
		add(item);
		return item;
	}
}
