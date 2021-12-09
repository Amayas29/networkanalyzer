CURRENT=$(pwd)

java -jar --module-path $CURRENT/javafx/macos --add-modules javafx.controls,javafx.fxml networkanalyzer.jar
