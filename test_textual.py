from textual.app import App
from textual.widgets import OptionList

class TestApp(App):
    def compose(self):
        yield OptionList(id="olist")
    
    def on_mount(self):
        ol = self.query_one("#olist", OptionList)
        ol.add_option("test1")
        ol.add_option("test2")

if __name__ == "__main__":
    app = TestApp()
    app.run(headless=True)
