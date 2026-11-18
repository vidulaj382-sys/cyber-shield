// Cyber Shield: Cybersecurity and Management System
// Wires the core (namespace cyber) to the FLTK windows.
// main() only creates the App and runs it; the App holds everything that must live
// as long as the program (so there are no global variables).
#include <FL/Fl.H>

#include "core/Logger.h"
#include "core/SecurityManager.h"
#include "gui/LoginWindow.h"
#include "gui/MainWindow.h"
#include "gui/SplashWindow.h"
#include "gui/Theme.h"

class App {
public:
    App(int argc, char** argv) : argc(argc), argv(argv) {
        cyber::Logger::setFile("cybershield.log");
        if (!manager.autoLoad(dataFile)) // first start: no data file yet
            manager.loadDemoIncidents();
    }

    ~App() {
        manager.autoSave(dataFile);
        delete mainWindow; // the windows must go before the manager they refer to
        delete login;
    }

    int run() {
        buildWindows();
        // Splash screen first; when its loading bar is full, the login window opens.
        splash = new SplashWindow([this] {
            Fl::delete_widget(splash);
            splash = nullptr;
            login->show(argc, argv);
        });
        splash->start();
        return Fl::run();
    }

private:
    void buildWindows() {
        mainWindow = new MainWindow(
            manager,
            [this] { // Logout
                manager.logout();
                login->reset();
                login->show();
                mainWindow->hide();
            },
            [this] { // Dark / light button: rebuild after the click has finished
                Fl::add_timeout(0.0, [](void* self) { static_cast<App*>(self)->switchTheme(); }, this);
            });
        login = new LoginWindow(manager, [this] {
            mainWindow->onLogin();
            mainWindow->show();
            login->hide();
        });
    }

    // Every widget takes its colours when it is created, so changing the theme
    // means building the windows again with the other palette.
    void switchTheme() {
        int page = mainWindow->currentPageIndex();
        int x = mainWindow->x(), y = mainWindow->y();

        mainWindow->hide();
        delete mainWindow;
        delete login;
        theme::setLight(!theme::isLight);
        buildWindows();

        mainWindow->position(x, y); // same place on the screen
        mainWindow->show();
        mainWindow->onLogin();
        mainWindow->showPage(page); // same page as before
    }

    int argc;
    char** argv;
    const char* dataFile = "incidents.dat";
    cyber::SecurityManager manager;
    SplashWindow* splash = nullptr;
    LoginWindow* login = nullptr;
    MainWindow* mainWindow = nullptr;
};

int main(int argc, char** argv) {
    theme::apply();
    App app(argc, argv);
    return app.run();
}
