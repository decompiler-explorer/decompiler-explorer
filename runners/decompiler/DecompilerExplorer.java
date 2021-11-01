/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decompile an entire program

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;


import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;
import ghidra.framework.Application;

public class DecompilerExplorer extends GhidraScript  {

	@Override
	public void run() throws Exception {
		File outputFile = new File(getScriptArgs()[0]);
		CppExporter cppExporter = new CppExporter();
		List<Option> options = new ArrayList<Option>();
		options.add(new Option(CppExporter.CREATE_HEADER_FILE, true));
		cppExporter.setOptions(options);
		cppExporter.setExporterServiceProvider(state.getTool());
		cppExporter.export(outputFile, currentProgram, null, monitor);
	}
}
