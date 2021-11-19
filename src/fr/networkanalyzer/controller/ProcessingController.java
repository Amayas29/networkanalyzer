package fr.networkanalyzer.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.Frame;
import fr.networkanalyzer.model.IField;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.FlowPane;

public class ProcessingController {

	@FXML
	private ListView<String> offsetList;

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
	private FlowPane frameFlow;

	private Analyzer analyzer;

	private List<Label> lastSelected;
	private Map<TreeItem<String>, List<Label>> childrens;

	private int remainingLength;

	private final int maxLength;

	private int currentByteLength;

	private String offset;

	private ObservableList<String> offsets;

	public ProcessingController(Analyzer analyzer) {
		this.analyzer = analyzer;
		maxLength = 47;
		remainingLength = maxLength;
		currentByteLength = 0;
		lastSelected = new ArrayList<>();
		childrens = new HashMap<>();
	}

	@FXML
	public void initialize() {

		fillTable();
		rootItem = new TreeItem<String>();
		viewTree.setRoot(rootItem);
		viewTree.setShowRoot(false);
	}

	@FXML
	void showFrame(MouseEvent event) {
		FrameView frameView = frameTable.getSelectionModel().getSelectedItem();

		if (frameView == null)
			return;

		Frame frame = frameView.getFrame();

		rootItem.getChildren().clear();
		frameFlow.getChildren().clear();
		childrens.clear();
		lastSelected.clear();
		remainingLength = maxLength;
		currentByteLength = 0;

		offset = "0000";
		offsets = FXCollections.observableArrayList("0x" + offset);
		offsetList.setItems(offsets);

		showDataLink(frame);
		showNetwork(frame);
		showTransport(frame);
		showApplication(frame);

		viewTree.getSelectionModel().selectedItemProperty().addListener((observable, oldValue, newValue) -> {

			if (newValue == null)
				return;

			clearSelection();

			for (Label label : childrens.get(newValue)) {
				label.getStyleClass().add("selected");
				lastSelected.add(label);
			}
		});

	}

	private void showDataLink(Frame frame) {
		showLayer(frame, frame.getFieldsDataLink(), "Ethernet");
	}

	private void showNetwork(Frame frame) {
		showLayer(frame, frame.getFieldsNetwork(), "Ip");
	}

	private void showTransport(Frame frame) {
		showLayer(frame, frame.getFieldsTransport(), "Udp");
	}

	private void showApplication(Frame frame) {
		showLayer(frame, frame.getFieldsApplication(), "Dhcp");
	}

	private void showLayer(Frame frame, List<IField> fields, String name) {

		TreeItem<String> tree = new TreeItem<>(name);

		for (IField field : fields)
			addTreeField(field, tree, true);

		setChildren(tree);

		rootItem.getChildren().add(tree);
	}

	private void initCols() {
		noCol.setCellValueFactory(new PropertyValueFactory<>("no"));
		srcCol.setCellValueFactory(new PropertyValueFactory<>("src"));
		destCol.setCellValueFactory(new PropertyValueFactory<>("dest"));
		protoCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
		lengthCol.setCellValueFactory(new PropertyValueFactory<>("lenght"));
	}

	private void fillTable() {
		initCols();
		List<Frame> frames = analyzer.getFrames();
		ObservableList<FrameView> frameViews = FXCollections.observableArrayList();
		for (int i = 0; i < frames.size(); i++)
			frameViews.add(new FrameView(frames.get(i), i + 1));

		frameTable.setItems(frameViews);
	}

	private void addLabel(IField field, TreeItem<String> correspondingTree) {

		List<Label> labels = childrens.get(correspondingTree);

		if (labels == null)
			labels = new ArrayList<>();

		String value = field.getValue();

		// Length in bits
		int len = field.getLength();

		// If is a modulo 8 then we add a space at the end
		if (len % 8 == 0) {
			value = value.concat(" ");
			currentByteLength = 0;
		}

		// otherwise the accumulator is incremented and if a byte is accumulated, a
		// space is added.
		else {
			currentByteLength += len;
			if (currentByteLength % 8 == 0) {
				value = value.concat(" ");
				currentByteLength = 0;
			}
		}

		// Number of characters
		len = value.length();

		if (len > remainingLength) {
			offset = String.valueOf(Integer.parseInt(offset, 10) + 10);
			for (; offset.length() < 4;)
				offset = "0" + offset;

			offsets.add("0x" + offset);

			Label firstL = new Label(value.substring(0, remainingLength));
			firstL.getStyleClass().add("labelByte");
			firstL.getStyleClass().add("label_frame");
			frameFlow.getChildren().add(firstL);

			String secondValue = value.substring(remainingLength);
			if (secondValue.charAt(0) == ' ') {
				secondValue = secondValue.substring(1);

			}
			Label secondL = new Label(secondValue);
			secondL.getStyleClass().add("labelByte");
			secondL.getStyleClass().add("label_frame");
			frameFlow.getChildren().add(secondL);

			remainingLength = maxLength;

			handler(correspondingTree, firstL, secondL);

			labels.add(firstL);
			labels.add(secondL);
			childrens.put(correspondingTree, labels);

			return;
		}

		remainingLength -= len;

		Label label = new Label(value);
		label.getStyleClass().add("labelByte");
		label.getStyleClass().add("label_frame");
		frameFlow.getChildren().add(label);

		handler(correspondingTree, label);

		labels.add(label);
		childrens.put(correspondingTree, labels);
	}

	private void handler(TreeItem<String> tree, Label... labels) {

		for (Label l : labels) {

			l.addEventHandler(MouseEvent.MOUSE_CLICKED, e -> {
				clearSelection();
				viewTree.getSelectionModel().select(tree);
				lastSelected.add(l);
			});
		}
	}

	private void clearSelection() {
		for (Label label : lastSelected)
			label.getStyleClass().remove("selected");

		lastSelected.clear();

	}

	private TreeItem<String> addTreeField(IField field, TreeItem<String> root, boolean first) {

		TreeItem<String> fieldItem = new TreeItem<>(field.toString());
		root.getChildren().add(fieldItem);

		if (first)
			addLabel(field, fieldItem);

		if (field.getChildrens() == null)
			return fieldItem;

		for (IField f : field.getChildrens())
			childrens.put(addTreeField(f, fieldItem, false), childrens.get(fieldItem));

		return fieldItem;
	}

	private void setChildren(TreeItem<String> tree) {
		List<Label> childs = new ArrayList<>();

		for (TreeItem<String> c : tree.getChildren())
			childs.addAll(childrens.get(c));

		childrens.put(tree, childs);
	}
}