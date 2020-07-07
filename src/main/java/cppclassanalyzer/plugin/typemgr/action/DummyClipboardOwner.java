package cppclassanalyzer.plugin.typemgr.action;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.Transferable;

final class DummyClipboardOwner implements ClipboardOwner {

	static final DummyClipboardOwner DUMMY = new DummyClipboardOwner();

	private DummyClipboardOwner() {
	}

	@Override
	public void lostOwnership(Clipboard clipboard, Transferable contents) {
	}

}
