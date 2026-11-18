#pragma once
// The splash screen: logo, name and a loading bar for about two seconds, then it
// calls the function it was given (which opens the login window).
#include <functional>
#include <FL/Fl_Window.H>

class SplashWindow : public Fl_Window {
public:
    explicit SplashWindow(std::function<void()> onDone);
    ~SplashWindow() override;

    void start(); // show the window and start the loading bar

protected:
    void draw() override;

private:
    static void tick(void* self);

    std::function<void()> onDone;
    double progress = 0.0; // 0 .. 1
};
