
CURRENT=$(pwd)

linux:
	bash scripts/run_linux.sh

macos:
	bash scripts/run_macos.sh

windows:
	scripts/windows.bat
	
terminal:
	java -jar networkanalyzer-terminal.jar

all:
	linux
