package cppclassanalyzer.database.utils;

public class TransactionHandler {

	private final TransactionStarter starter;
	private final TransactionEnder ender;
	private final LongStack transactions;

	public TransactionHandler(TransactionStarter starter, TransactionEnder ender) {
		this.starter = starter;
		this.ender = ender;
		this.transactions = new LongStack();
	}

	public void startTransaction() {
		startTransaction(null);
	}

	public void startTransaction(String description) {
		transactions.push(starter.startTransaction(description));
	}

	public void endTransaction() {
		endTransaction(true);
	}

	public void endTransaction(boolean commit) {
		long id = transactions.pop();
		ender.endTransaction(id, commit);
	}

	@FunctionalInterface
	public static interface TransactionStarter {
		long startTransaction(String description);
	}

	@FunctionalInterface
	public static interface TransactionEnder {
		void endTransaction(long id, boolean commit);
	}
}