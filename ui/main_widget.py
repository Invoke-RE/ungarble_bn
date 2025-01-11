from binaryninjaui import Pane, WidgetPane, UIActionHandler, UIActionHandler, UIAction, Menu, UIContext, UIContextNotification
from binaryninja.log import Logger
from PySide6 import QtCore
from PySide6.QtCore import Slot
from PySide6.QtWidgets import QVBoxLayout, QWidget, QTableWidget, QFileDialog, QTableWidgetItem, QPushButton, QMenu
import re
from ..core.ungarble import EmulateLocationsWrapper, FindLocationsWrapper, Ungarble, EmulateLocations, FindLocations
import time

instance_id = 0
logger = Logger(session_id=0, logger_name=__name__)

# Class to handle UI context notifications. This will be used to listen for view and address
# changes and update the pane accordingly.
class UngarbleNotifications(UIContextNotification):
    def __init__(self, widget):
        UIContextNotification.__init__(self)
        self.widget = widget
        self.widget.destroyed.connect(self.destroyed)

    def destroyed(self):
        UIContext.unregisterNotification(self)

    def OnViewChange(self, context, frame, type):
        pass

    def OnAddressChange(self, context, frame, view, location):
        pass

class UngarblePaneWidget(QWidget, UIContextNotification):
    def __init__(self, bv):
        global instance_id
        QWidget.__init__(self)
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)
        layout = QVBoxLayout()
        layout.addStretch()
        self.bv = bv
        #There's probably a better way to get the original PE data
        self.pe = open(re.sub("\.bndb", "", self.bv.file.filename), 'rb').read()

        # Add table widget
        self.tableWidget = QTableWidget(self)
        self.tableWidget.setFixedSize(800, 600)  # Set fixed size for the table widget
        self.tableWidget.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tableWidget.customContextMenuRequested.connect(self.showContextMenu)
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels(["Start Address", "End Address", "Ungarbled String"])

        self.tableWidget.setColumnWidth(0, 500)  # Set width for "Start Address"
        self.tableWidget.setColumnWidth(1, 500)  # Set width for "End Address"
        self.tableWidget.setColumnWidth(2, 700)  # Set width for "Ungarbled String"

        # Resize rows and columns to fit contents
        #self.tableWidget.resizeRowsToContents()
        self.tableWidget.resizeColumnsToContents()

        self.tableWidget.cellClicked.connect(self.onTableCellClicked)

        layout.addWidget(self.tableWidget, stretch=1)

        # Button to get target locations
        self.getTargetLocationsBtn = QPushButton("Get Target Locations", self)
        self.getTargetLocationsBtn.clicked.connect(self.getTargetLocations)
        layout.addWidget(self.getTargetLocationsBtn)

        self.ungarbleLocationsBtn = QPushButton("Ungarble Locations", self)
        self.ungarbleLocationsBtn.clicked.connect(self.ungarbleLocations)
        layout.addWidget(self.ungarbleLocationsBtn)

        layout.addStretch()
        self.setLayout(layout)
        instance_id += 1

        # Connect to signals to update table when events occur
        self.findLocations = FindLocationsWrapper()
        self.findLocations.update_ui_signal.connect(self.updateData)
        self.findLocations.finished.connect(self.finished)
        self.emulateLocations = EmulateLocationsWrapper()
        self.emulateLocations.update_ui_signal.connect(self.updateTable)
        self.items = []

        # Populate initial state
        #self.updateState()

        # Set up view and address change notifications
        self.notifications = UngarbleNotifications(self)

    def updateState(self):
        # Get the currently active view frame for this group of panes. There can be
        # multiple view frames in a single window, or the pane could be popped out
        # into its own window. UIContext.currentViewFrameForWidget will determine
        # the best view frame to use for context.
        frame = UIContext.currentViewFrameForWidget(self)

        # Update UI according to the active frame
        if frame:
            self.datatype.setText(frame.getCurrentView())
            view = frame.getCurrentViewInterface()
            self.data = view.getData()
            self.offset.setText(hex(view.getCurrentOffset()))
        else:
            self.datatype.setText("None")
            self.data = None
    
    def getTargetLocations(self):
        logger.log_info("[ + ] Getting target locations")
        self.findLocations.start(self.pe, self.bv)

    def ungarbleLocations(self, data):
        logger.log_info("[ + ] Ungarbling all locations")
        rowCount = self.tableWidget.rowCount()

        addresses = []
        for row in range(0, rowCount):
            startAddress = int(self.tableWidget.item(row, 0).text(), 16)
            endAddress = int(self.tableWidget.item(row, 1).text(), 16)
            currentStr = self.tableWidget.item(row, 2).text()
            addresses.append({'start': startAddress, 'end': endAddress, 'current': currentStr})

        self.emulateLocations.start(addresses, self.pe)

    @Slot()
    def finished(self):
        for item in self.items:
            self.addDataToTable(item, "")

    @Slot(int, int)
    def updateData(self, start, end):
        #self.tableWidget.insertRow(row_position)
        #self.tableWidget.setItem(row_position, 0, QTableWidgetItem("0x%x" % start))
        #self.tableWidget.setItem(row_position, 1, QTableWidgetItem("0x%x" % end))
        #self.tableWidget.setItem(row_position, 2, QTableWidgetItem(result))
        self.items.append({
            'start': start,
            'end': end,
        })

    @Slot(int, int, str, int)
    def updateTable(self, start, end, result, row_position):
        #self.tableWidget.insertRow(row_position)
        self.tableWidget.setItem(row_position, 0, QTableWidgetItem("0x%x" % start))
        self.tableWidget.setItem(row_position, 1, QTableWidgetItem("0x%x" % end))
        self.tableWidget.setItem(row_position, 2, QTableWidgetItem(result))

    def addDataToTable(self, data, ungarbled_string):
        row_position = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_position)

        self.tableWidget.setItem(row_position, 0, QTableWidgetItem("0x%x" % data['start']))
        self.tableWidget.setItem(row_position, 1, QTableWidgetItem("0x%x" % data['end']))
        self.tableWidget.setItem(row_position, 2, QTableWidgetItem(ungarbled_string))

    def onTableCellClicked(self, row, column):
        if column == 0 or column == 1:
            item = self.tableWidget.item(row, column)
            if item:
                self.bv.navigate(self.bv.view, int(item.text(), 16))

    def showContextMenu(self, position):
        # Get the row and column of the right-clicked cell
        index = self.tableWidget.indexAt(position)
        rightClickedRow = index.row()
        startAddress = int(self.tableWidget.item(rightClickedRow, 0).text(), 16)
        endAddress = int(self.tableWidget.item(rightClickedRow, 1).text(), 16)

        menu = QMenu()
        action1 = menu.addAction("Ungarble String")
        action = menu.exec_(self.tableWidget.viewport().mapToGlobal(position))
        if action == action1:
            result = self.ungarbleString(startAddress, endAddress)
            #Sets result 
            self.tableWidget.setItem(rightClickedRow, 2, QTableWidgetItem(result))

    def ungarbleString(self, startAddress, endAddress):
        logger.log_info(f"Emulating from: 0x{startAddress:2x} to 0x{endAddress:2x}")
        
        rstr = Ungarble.run_vstack(self.pe, startAddress, endAddress)
        logger.log_info(f"Found string: {rstr}")
        return rstr

    def contextMenuEvent(self, event):
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

    @staticmethod
    def createPane(context):
        if context.context and context.binaryView:
            widget = UngarblePaneWidget(context.binaryView)
            pane = WidgetPane(widget, "Ungarble")
            context.context.openPane(pane)
            logger.log_info(context.binaryView)

    @staticmethod
    def canCreatePane(context):
        return context.context and context.binaryView