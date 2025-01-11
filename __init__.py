from .ui.main_widget import *

UIAction.registerAction("Ungarble Pane")
UIActionHandler.globalActions().bindAction(
  "Ungarble Pane", UIAction(UngarblePaneWidget.createPane, UngarblePaneWidget.canCreatePane)
)
Menu.mainMenu("Plugins").addAction("Ungarble Pane", "Ungarble")