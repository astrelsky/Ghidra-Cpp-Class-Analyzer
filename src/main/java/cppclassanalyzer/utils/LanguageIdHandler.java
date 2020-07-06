package cppclassanalyzer.utils;

import ghidra.program.model.lang.LanguageID;

/**
 * {@link LanguageID} helper class
 */
public class LanguageIdHandler {

	private final String[] id;

	/**
	 * Constructs a new LanguageIdHandler
	 * @param id the language id
	 */
	public LanguageIdHandler(LanguageID id) {
		this.id = id.getIdAsString().split(":");
	}

	/**
	 * Gets the processor name
	 * @return the processor name
	 */
	public String getProcessor() {
		return id[0];
	}

	/**
	 * Gets the processor endianess
	 * @return the processor endianess
	 */
	public String getEndianess() {
		return id[1];
	}

	/**
	 * Gets the address size
	 * @return the address size
	 */
	public String getAddressSize() {
		return id[2];
	}

	/**
	 * Gets the processor variant
	 * @return the processor variant
	 */
	public String getVariant() {
		return id[3];
	}
}
