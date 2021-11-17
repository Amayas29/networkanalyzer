package fr.networkanalyzer.controller;

import java.util.List;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.Field;
import fr.networkanalyzer.model.Frame;
import fr.networkanalyzer.model.layers.Layer;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.VBox;

public class ProcessingController {

	@FXML
	private TreeView<String> viewTree;

	private TreeItem<String> rootItem;

	@FXML
	private TableColumn<FrameView, SimpleStringProperty> destCol;

	@FXML
	private TableView<FrameView> frameTable;

	@FXML
	private TableColumn<FrameView, SimpleIntegerProperty> lengthCol;

	@FXML
	private TableColumn<FrameView, SimpleIntegerProperty> noCol;

	@FXML
	private TableColumn<FrameView, SimpleStringProperty> protoCol;

	@FXML
	private TableColumn<FrameView, SimpleStringProperty> srcCol;

	@FXML
	private VBox frameVB;

	private Analyzer analyzer;

	public ProcessingController(Analyzer analyzer) {
		this.analyzer = analyzer;
	}

	@FXML
	public void initialize() {
		fillTable();
		rootItem = new TreeItem<String>();
		viewTree.setRoot(rootItem);
	}

	private void fillTable() {
		initCols();
		List<Frame> frames = analyzer.getFrames();
		ObservableList<FrameView> frameViews = FXCollections.observableArrayList();
		for (int i = 0; i < frames.size(); i++)
			frameViews.add(new FrameView(frames.get(i), i + 1));

		frameTable.setItems(frameViews);

	}

	@FXML
	void showFrame(MouseEvent event) {
		FrameView frameView = frameTable.getSelectionModel().getSelectedItem();

		if (frameView == null)
			return;

		Frame frame = frameView.getFrame();

		showDataLink(frame);
		showNetwork(frame);
		showTransport(frame);
		showApplication(frame);
	}

	private void showDataLink(Frame frame) {
		List<Field> fields = frame.getFieldsDataLink();
		TreeItem<String> ethernetTree = new TreeItem<>("Ethernet");

		for (Field field : fields) {
			TreeItem<String> fieldItem = new TreeItem<>(field.getName());
			ethernetTree.getChildren().add(fieldItem);
		}

		rootItem.getChildren().add(ethernetTree);

	}

	private void showNetwork(Frame frame) {

	}

	private void showTransport(Frame frame) {

	}

	private void showApplication(Frame frame) {

	}

	private void initCols() {
		noCol.setCellValueFactory(new PropertyValueFactory<>("no"));
		srcCol.setCellValueFactory(new PropertyValueFactory<>("src"));
		destCol.setCellValueFactory(new PropertyValueFactory<>("dest"));
		protoCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
		lengthCol.setCellValueFactory(new PropertyValueFactory<>("lenght"));
	}
}