//@category CppClassAnalyzer
import cppclassanalyzer.script.CppClassAnalyzerGhidraScript;

public class CppClassAnalyzerTestScript extends CppClassAnalyzerGhidraScript {

	@Override
	public void run() throws Exception {
		println("The current class is " + getClass().getSimpleName());
		println("Its super class is " + getClass().getSuperclass().getName());
		println("The current manager is " + currentManager.getName());
	}
}