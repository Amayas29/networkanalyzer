package fr.networkanalyzer.application;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.AnalyzerParser;
import fr.networkanalyzer.model.Frame;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerFileErrorsException;

public class TerminalMain {
	public static void main(String[] args) {

		System.out.println(
				"--------------------- Terminal Version | autors : Amayas SADI and Hamid KOLLI ---------------------");

		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));

		File file = null;

		Analyzer analyzer = null;

		while (true) {
			System.out.print("\n\n\t - Input the filename : ");
			file = new File(read(in));

			try {
				AnalyzerParser.verifyFile(file);
			} catch (NetworkAnalyzerFileErrorsException e) {
				System.out.println("\n\t * Error " + e.getMessage());
				continue;
			}

			try {
				analyzer = AnalyzerParser.parse(file);
			} catch (NetworkAnalyzerException e1) {
				System.out.println("\t \t The format of this file is not compatible \n");
				continue;
			}

			break;
		}

		System.out.println("\n\t*** Press ENTER to continue ***");
		read(in);

		while (true) {

			System.out.println("\t>>> Select an action : \n");
			displayMain();

			int choose;
			try {
				choose = Integer.parseInt(read(in));
			} catch (Exception e) {
				continue;
			}

			switch (choose) {
			case 0: {
				System.out.println(analyzer);
				System.out.println("\n\t*** Press ENTER to continue ***");
				read(in);
				break;
			}

			case 1: {
				System.out.println("\t\t Enter the id frame");
				try {
					int c = Integer.parseInt(read(in));
					boolean b = true;

					for (Frame f : analyzer.getFrames()) {
						if (f.getId() == c) {
							System.out.println(f);
							b = false;
							break;
						}
					}

					if (b)
						System.out.println("\t\t The frame doesn't exist");

				} catch (Exception e) {
					System.out.println("\t\t Invalid number \n");
				}

				System.out.println("\n\t*** Press ENTER to continue ***");
				read(in);

			}

			case 2: {
				try {
					AnalyzerParser.saveAll(analyzer);
				} catch (NetworkAnalyzerException e) {

				}

				continue;
			}

			case 3: {
				System.out.println("\t\t please enter the id frame");
				try {
					int c = Integer.parseInt(read(in));
					boolean b = true;

					for (Frame f : analyzer.getFrames()) {
						if (f.getId() == c) {
							AnalyzerParser.save(f);
							b = false;
							break;
						}
					}

					if (b)
						System.out.println("\t\t The frame doesn't exist");

				} catch (Exception e) {
					System.out.println("\t\t Invalid number \n");
				}

				System.out.println("\n\t*** Press ENTER to continue ***");
				read(in);
				continue;
			}

			case 4: {
				System.out.println("\t Good bye");
				System.out.println("\n\t*** Press ENTER to exit ***");
				read(in);
				System.exit(0);
				continue;
			}

			default:
				System.out.println("\t Invalid number \n");
				System.out.println("\n\t*** Press ENTER to continue ***");
				read(in);
				continue;
			}

		}

	}

	private static String read(BufferedReader in) {
		try {
			return in.readLine();
		} catch (IOException e) {
			return null;
		}
	}

	private static void displayMain() {

		System.out.println("\t+------------------------+");
		System.out.println("\t| 0 - Display all frames |");
		System.out.println("\t| 1 - Display frame      |");
		System.out.println("\t| 2 - Save all frames    |");
		System.out.println("\t| 3 - Save frame         |");
		System.out.println("\t| 4 - Exit               |");
		System.out.println("\t+------------------------+");

	}

}
