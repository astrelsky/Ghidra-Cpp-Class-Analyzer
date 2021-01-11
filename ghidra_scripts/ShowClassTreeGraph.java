// Given a class name, render a graph with the entire class hierarchy (all supertypes and subtypes).
// @category CppClassAnalyzer
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.script.CppClassAnalyzerGhidraScript;
import docking.widgets.EventTrigger;
import ghidra.GhidraException;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.AttributedGraph;
import ghidra.service.graph.AttributedVertex;
import ghidra.service.graph.GraphDisplay;

import java.util.*;

public class ShowClassTreeGraph extends CppClassAnalyzerGhidraScript {

	@Override
	protected void run() throws Exception {
		String typeName = askString("Class name", "Enter name of the class to print the class tree of");
		ClassTypeInfoDB type = currentManager.getTypeStream()
			.filter(ty -> typeName.equalsIgnoreCase(ty.getName()))
			.findFirst()
			.orElseThrow(() -> new GhidraException("No type found with given name"));

		monitor.setMessage("Generating class tree graph");

		PluginTool tool = getState().getTool();
		GraphDisplayBroker service = tool.getService(GraphDisplayBroker.class);
		GraphDisplay display = service.getDefaultGraphDisplay(false, monitor);
		Map<Long, AttributedVertex> vertices = new HashMap<>();

		AttributedGraph graph = new AttributedGraph();
		AttributedVertex typeVertex = graph.addVertex(type.getFullName());
		vertices.put(type.getClassDataTypeId(), typeVertex);

		Set<Long> subtypes = new HashSet<>();
		subtypes.add(type.getClassDataTypeId());

		while (!subtypes.isEmpty()) {
			Set<Long> currentParents = new HashSet<>(subtypes);
			subtypes.clear();

			for (ClassTypeInfoDB candidate : currentManager.getTypes()) {
				for (ClassTypeInfoDB parent : candidate.getParentModels()) {
					if (monitor.isCancelled()) {
						return;
					}

					long parentId = parent.getClassDataTypeId();

					if (currentParents.contains(parentId)) {
						subtypes.add(candidate.getClassDataTypeId());
						AttributedVertex vertex = graph.addVertex(candidate.getFullName());

						vertices.put(candidate.getClassDataTypeId(), vertex);
						graph.addEdge(vertices.get(parentId), vertex);
					}
				}
			}
		}

		Deque<ClassTypeInfoDB> supertypes = new ArrayDeque<>();
		supertypes.push(type);

		while (!supertypes.isEmpty()) {
			ClassTypeInfoDB supertype = supertypes.pop();
			AttributedVertex vertex = vertices.computeIfAbsent(supertype.getClassDataTypeId(),
				(key) -> new AttributedVertex(supertype.getFullName()));

			for (ClassTypeInfoDB parent : supertype.getParentModels()) {
				if (monitor.isCancelled()) {
					return;
				}

				AttributedVertex parentVertex = vertices.computeIfAbsent(parent.getClassDataTypeId(),
					(key) -> new AttributedVertex(parent.getFullName()));

				supertypes.push(parent);
				graph.addEdge(parentVertex, vertex);
			}
		}

		display.setGraph(graph, "Class Tree", false, monitor);
		display.selectVertices(Set.of(typeVertex), EventTrigger.MODEL_CHANGE);
	}
}
