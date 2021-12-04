package fr.networkanalyzer.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import fr.networkanalyzer.model.Analyzer;
import fr.networkanalyzer.model.Frame;
import fr.networkanalyzer.model.exceptions.NetworkAnalyzerException;
import fr.networkanalyzer.model.fields.IField;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.FlowPane;
import javafx.stage.Stage;

public class ProcessingController {

	@FXML
	private FlowPane offsetList;

	@FXML
	private TreeView<String> viewTree;

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
	private ListView<Label> errorsListView;

	@FXML
	private FlowPane frameFlow;

	@FXML
	private ScrollPane scrollFrame;

	private TreeItem<String> rootItem;

	private Analyzer analyzer;

	private List<Label> lastSelected;

	private Map<TreeItem<String>, List<Label>> childrens;

	private int remainingLength;

	private final int maxLength;

	private int currentByteLength;

	private String offset;

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
		fillErrors();
		rootItem = new TreeItem<String>();
		viewTree.setRoot(rootItem);
		viewTree.setShowRoot(false);

		offsetList.setMouseTransparent(true);
		offsetList.setFocusTraversable(false);

		errorsListView.setFocusTraversable(false);
	}

	@FXML
	public void exitApp() {
		System.exit(0);
	}

	@FXML
	public void returnToPrincipalPage(ActionEvent event) {

		Stage stage = (Stage) offsetList.getScene().getWindow();
		Parent root = null;

		try {
			root = FXMLLoader.load(getClass().getResource("/fr/networkanalyzer/view/fxml/main.fxml"));
		} catch (IOException e) {
			return;
		}

		Scene scene = new Scene(root);
		stage.setScene(scene);
	}

	@FXML
	void showFrame(MouseEvent event) {
		FrameView frameView = frameTable.getSelectionModel().getSelectedItem();

		if (frameView == null)
			return;

		Frame frame = frameView.getFrame();

		rootItem.getChildren().clear();
		frameFlow.getChildren().clear();
		offsetList.getChildren().clear();
		childrens.clear();
		clearSelection();
		remainingLength = maxLength;
		currentByteLength = 0;
		offset = "0000";

		offsetList.getChildren().add(newOffset());

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
		try {
			showLayer(frame, frame.getFieldsDataLink(), frame.getDataLinkName());
		} catch (NetworkAnalyzerException e) {
			System.out.println(e.getMessage());
		}
	}

	private void showNetwork(Frame frame) {
		try {
			showLayer(frame, frame.getFieldsNetwork(), frame.getNetworkName());
		} catch (NetworkAnalyzerException e) {
			System.out.println(e.getMessage());
		}
	}

	private void showTransport(Frame frame) {
		try {
			showLayer(frame, frame.getFieldsTransport(), frame.getTransportName());
		} catch (NetworkAnalyzerException e) {
			System.out.println(e.getMessage());
		}
	}

	private void showApplication(Frame frame) {
		try {
			showLayer(frame, frame.getFieldsApplication(), frame.getApplicationName());
		} catch (NetworkAnalyzerException e) {
			System.out.println(e.getMessage());
		}
	}

	private void showLayer(Frame frame, List<IField> fields, String name) {

		TreeItem<String> tree = new TreeItem<>(name);

		for (IField field : fields) {
			System.out.println(field);
			addTreeField(field, tree, true);
		}

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

	private void fillErrors() {
		List<Label> labels = new ArrayList<>();
		Label label;
		for (String error : analyzer.getErrors()) {
			label = new Label(error);
			label.getStyleClass().add("errorFrameLabel");
			labels.add(label);
		}

		ObservableList<Label> items = FXCollections.observableArrayList(labels);
		errorsListView.setItems(items);
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
		int toAdd;
		Label label;
		String toAddValue;

		while (len > 0) {
			toAdd = len - remainingLength;

			if (toAdd < 0) {
				label = new Label(value);
				label.getStyleClass().add("labelByte");
				frameFlow.getChildren().add(label);
				labels.add(label);
				remainingLength -= len;
				len = 0;
				handler(correspondingTree, label);
				continue;
			}

			offset = String.valueOf(Integer.parseInt(offset, 10) + 10);
			for (; offset.length() < 4;)
				offset = "0" + offset;

			offsetList.getChildren().add(newOffset());

			toAddValue = value.substring(0, remainingLength);

			try {
				value = value.substring(remainingLength).stripLeading();
			} catch (IndexOutOfBoundsException e) {
				value = "";
			}

			remainingLength = maxLength;

			len = value.length();

			label = new Label(toAddValue);
			label.getStyleClass().add("labelByte");
			frameFlow.getChildren().add(label);
			labels.add(label);

			handler(correspondingTree, label);
		}

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

	private Label newOffset() {
		Label label = new Label("0x".concat(offset));
		label.getStyleClass().add("labelOffset");
		return label;
	}
}