"""
gui – PyQt6 application shell for Kamerka-Plus-GUI.

Modules
-------
main_window     QMainWindow that hosts the PyVista globe widget (right pane)
                and the DetailsPanel (left pane).  Connects spike picker events
                to the details panel so clicking a 3-D spike shows the
                associated IP banner and vulnerability logs.
details_panel   QWidget sidebar that renders IP metadata, open-port banners,
                and NucleiResult findings for the currently selected device.
launch          Entry-point: initialises Django settings for standalone DB
                access, creates the QApplication and MainWindow, then starts
                the Qt event loop.
"""
