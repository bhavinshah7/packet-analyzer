package pktanalyzer;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.PrintWriter;

public class Main {

	public static void main(String argv[]) {

		Main main = new Main();

		if (argv.length < 1) {
			System.err.println("USAGE: java packetanalyzer.Main <FILENAME>");
			System.exit(1);
		}
		
		main.analyze(argv);
	}
	
	
	private void analyze(String argv[]) {
		for (int i = 0; i < argv.length; i++) {
			try {

				if (!isFileValid(argv[i])) {
					continue;
				}
				
				Parser parser = new Parser(new FileInputStream(argv[i]));
				parser.parse();
							
			} catch (Exception e) {
				e.printStackTrace();
				System.exit(1);
			} finally {
				
			}
		}
	}
	
	private boolean isFileValid(String filename) {
		File f = new File(filename); 
		System.out.println(new File(".").getAbsolutePath());
		if (!f.exists()) {
			System.err.println(filename + ": No such file!");
			return false;
		}

		String fileExtension = getFileExtension(f);
		if (!"bin".equals(fileExtension)) {
			System.err.println(filename + ": Invalid file extension!");
			return false;
		}

		return true;
	}

	private String getFileExtension(File file) {
		String name = file.getName();
		try {
			return name.substring(name.lastIndexOf(".") + 1);
		} catch (Exception e) {
			return "";
		}
	}

}