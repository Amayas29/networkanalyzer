CURRENT=$(pwd)

java -jar --module-path $CURRENT/javafx/linux --add-modules javafx.controls,javafx.fxml networkanalyzer.jar
