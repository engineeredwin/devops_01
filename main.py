import sys
import random
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QHBoxLayout, QMenuBar, QAction
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class GraphWidget(FigureCanvas):
    def __init__(self, parent=None):
        self.figure = Figure()
        FigureCanvas.__init__(self, self.figure)
        self.setParent(parent)

    def plot_random_data(self, title):
        data = [random.randint(1, 10) for _ in range(10)]
        ax = self.figure.add_subplot(111)
        ax.plot(data, 'r-')
        ax.set_title(title)
        self.draw()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)

        # Create a main horizontal layout for the whole window
        main_layout = QHBoxLayout(self.central_widget)

        # Create a vertical layout for the menu bar
        menu_layout = QVBoxLayout()

        # Create a menu bar and add actions
        self.menu_bar = QMenuBar(self)
        self.menu_bar.setFixedWidth(150)
        self.menu_bar.setMaximumHeight(self.height())

        action1 = QAction('Option 1', self)
        action2 = QAction('Option 2', self)
        action3 = QAction('Option 3', self)

        menu = self.menu_bar.addMenu('Menu')
        menu.addAction(action1)
        menu.addAction(action2)
        menu.addAction(action3)

        # Add the menu bar to the menu layout
        menu_layout.addWidget(self.menu_bar)

        # Create a vertical layout for the graphs
        graph_layout = QVBoxLayout()

        # Create two horizontal layouts for top and bottom pairs of graphs
        top_layout = QHBoxLayout()
        bottom_layout = QHBoxLayout()

        # Create and add GraphWidgets to top_layout and bottom_layout
        graph1 = GraphWidget(self)
        graph2 = GraphWidget(self)
        graph3 = GraphWidget(self)
        graph4 = GraphWidget(self)
        graph1.plot_random_data("Graph1")
        graph2.plot_random_data("Graph2")
        graph3.plot_random_data("Graph3")
        graph4.plot_random_data("Graph4")
        top_layout.addWidget(graph1)
        top_layout.addWidget(graph2)
        bottom_layout.addWidget(graph3)
        bottom_layout.addWidget(graph4)

        # Add the top and bottom layouts to the graph layout
        graph_layout.addLayout(top_layout)
        graph_layout.addLayout(bottom_layout)

        # Add the menu layout and graph layout to the main layout
        main_layout.addLayout(menu_layout)
        main_layout.addLayout(graph_layout)

        self.setGeometry(100, 100, 950, 600)
        self.setWindowTitle('Four Graphs Example')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
