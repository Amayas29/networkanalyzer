package fr.networkanalyzer.model.tools;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import fr.networkanalyzer.model.exceptions.NetworkAnalyzerFileErrorsException;

public class ParsingTools {

	public static File reorganizeFile(File file) throws NetworkAnalyzerFileErrorsException {
		File newFile = new File(file.getName() + ".rg");
		BufferedWriter bufferedWriter = null;

		try (BufferedReader bufferedReader = new BufferedReader(new FileReader(file))) {

			bufferedWriter = new BufferedWriter(new FileWriter(newFile));

			String line;
			StringBuilder sb = new StringBuilder();
			StringBuilder indexs = new StringBuilder();
			String[] data;
			String oldOffset = "0";
			int index = 0;
			int inc = 0;
			int lengthLine = 0;
			int indexLine = 0;

			while ((line = bufferedReader.readLine()) != null) {

				data = line.split(" ");

				if (data.length == 0) {
					indexLine++;
					continue;
				}

				if (checkOffset(data[0], "0", 0)) {
					if (sb.length() != 0) {
						bufferedWriter.write(indexs.toString().concat(sb.toString().concat("\n")));
						inc++;
					}

					lengthLine = 0;
					oldOffset = "0";
					sb.setLength(0);
					indexs.setLength(0);
				}

				if (!checkOffset(oldOffset, data[0], lengthLine))
					continue;

				oldOffset = data[0];
				index += lengthLine;

				indexs.append(addPattern(indexLine, index * 2 + index + inc).concat(" "));
				lengthLine = 0;

				for (int i = 1; i < data.length; i++) {

					if (data[i].isBlank())
						continue;

					if (!checkByte(data[i]))
						break;

					sb.append(data[i].concat(" "));
					lengthLine++;
				}

				indexLine++;
			}

			if (sb.length() != 0) {
				bufferedWriter.write(indexs.toString().concat(sb.toString().concat("\n")));
				inc++;
				;
			}
		} catch (

		IOException e) {
			throw new NetworkAnalyzerFileErrorsException(e.getMessage());
		} finally {
			if (bufferedWriter != null)
				try {
					bufferedWriter.close();
				} catch (IOException e) {
					throw new NetworkAnalyzerFileErrorsException(e.getMessage());
				}
		}

		return newFile;
	}

	private static String addPattern(int l, int i) {
		return String.format("[%d,%d]", l, i);
	}

	public static boolean isPattern(String line) {
		return line.startsWith("[") && line.endsWith("]");
	}

	public static int getIndexPattern(String line) {
		String[] data = line.substring(1, line.length() - 1).split(",");
		return Integer.parseInt(data[1]);
	}

	public static int getLinePattern(String line) {
		String[] data = line.substring(1, line.length() - 1).split(",");
		return Integer.parseInt(data[0]);
	}

	private static boolean checkByte(String b) {

		if (b.length() != 2)
			return false;
		try {
			Integer.parseInt(b, 16);
			return true;
		} catch (NumberFormatException e) {
			return false;
		}

	}

	private static boolean checkOffset(String oldOffset, String newOffset, int lenghtLine) {
		try {
			return Integer.parseInt(oldOffset, 16) + lenghtLine == Integer.parseInt(newOffset, 16);
		} catch (NumberFormatException e) {
			return false;
		}
	}

}
