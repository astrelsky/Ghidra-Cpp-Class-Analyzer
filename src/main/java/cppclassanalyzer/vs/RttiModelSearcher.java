package cppclassanalyzer.vs;

import java.util.Comparator;
import java.util.Iterator;
import java.util.Objects;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import util.CollectionUtils;

import static cppclassanalyzer.vs.VsClassTypeInfo.DEFAULT_OPTIONS;

final class RttiModelSearcher {

	private final TypeDescriptorModel type;
	private AnyRttiModel any;

	RttiModelSearcher(TypeDescriptorModel type) {
		this.type = Objects.requireNonNull(type);
		this.any = AnyRttiModel.EMPTY;
		try {
			type.validate();
		} catch (InvalidDataTypeException e) {
			throw new IllegalArgumentException("The TypeDescriptorModel must be valid");
		}
	}

	static Rtti4Model findRtti4Model(Program program, Address addr, TaskMonitor monitor)
			throws CancelledException {
		Data data = program.getListing().getDataAt(addr);
		if (data != null) {
			Iterator<Reference> it = data.getReferenceIteratorTo();
			Iterator<Address> addresses = CollectionUtils.asStream(it)
				.map(Reference::getFromAddress)
				.sorted(Comparator.reverseOrder())
				.iterator();
			for (Address address : CollectionUtils.asIterable(addresses)) {
				monitor.checkCancelled();
				AnyRttiModel result = getAnyRttiModel(program, address);
				if (result.isPresent()) {
					// short circuit rtti4 comes after rtti3
					return result.getRtti4Model();
				}
			}
		}
		return null;
	}

	void search(TaskMonitor monitor) throws CancelledException {
		Program program = type.getProgram();
		Address addr = type.getAddress();
		Data data = program.getListing().getDataAt(addr);
		if (data != null) {
			Iterator<Reference> it = data.getReferenceIteratorTo();
			Iterator<Address> addresses = CollectionUtils.asStream(it)
				.map(Reference::getFromAddress)
				.sorted(Comparator.reverseOrder())
				.iterator();
			for (Address address : CollectionUtils.asIterable(addresses)) {
				monitor.checkCancelled();
				AnyRttiModel result = getAnyRttiModel(program, address);
				if (result.isPresent()) {
					this.any = result;
					return;
				}
			}
		}
	}

	AnyRttiModel getSearchResult() {
		return any;
	}

	private static AnyRttiModel getAnyRttiModel(Program program, Address address) {
		Listing listing = program.getListing();
		Data data = listing.getDataContaining(address);
		if (data != null) {
			if (data.getDataType().equals(Rtti4Model.getDataType(program))) {
				Rtti4Model model = new Rtti4Model(program, data.getAddress(), DEFAULT_OPTIONS);
				return new AnyRttiModel(model);
			}
			if (data.getDataType().equals(Rtti1Model.getDataType(program))) {
				if (data.getAddress().equals(address)) {
					Rtti3Model model = getValidRtti3Model(program, address);
					if (model != null) {
						return new AnyRttiModel(model);
					}
				}
			}
		}
		try {
			Address rtti4Address = address.subtract(Rtti4Model.getRtti0PointerComponentOffset());
			Rtti4Model model = new Rtti4Model(program, rtti4Address, DEFAULT_OPTIONS);
			model.validate();
			return new AnyRttiModel(model);
		} catch (InvalidDataTypeException e) {
		}
		Rtti3Model model = getValidRtti3Model(program, address);
		if (model != null) {
			return new AnyRttiModel(model);
		}
		return AnyRttiModel.EMPTY;
	}

	private static Rtti3Model getValidRtti3Model(Program program, Address address) {
		Rtti1Model rtti1 = new Rtti1Model(program, address, DEFAULT_OPTIONS);
		try {
			Address rtti3Address = rtti1.getRtti3Address();
			Rtti3Model model = new Rtti3Model(program, rtti3Address, DEFAULT_OPTIONS);
			model.validate();
			return model;
		} catch (InvalidDataTypeException e) {
			return null;
		}
	}

	static final class AnyRttiModel {

		private static final AnyRttiModel EMPTY = new AnyRttiModel(null);

		private final Object o;

		private AnyRttiModel(Object o) {
			this.o = o;
		}

		boolean isPresent() {
			return o != null;
		}

		boolean isRtti3Model() {
			return o instanceof Rtti3Model;
		}

		boolean isRtti4Model() {
			return o instanceof Rtti4Model;
		}

		Rtti3Model getRtti3Model() {
			if (isRtti3Model()) {
				return (Rtti3Model) o;
			}
			return null;
		}

		Rtti4Model getRtti4Model() {
			if (isRtti4Model()) {
				return (Rtti4Model) o;
			}
			return null;
		}
	}
}
