#include "LinkTab.h"
#include "GuiHelpers.h"

using namespace cyber;

namespace {
// Three links to try. The checker says Safe, Suspicious and Dangerous for them.
const char* kExamples[] = {"https://www.wikipedia.org/wiki/Cat",
                           "http://bit.ly/my-new-game",
                           "http://185.220.101.1/verify-your-bank-account/login"};
const char* kExampleNames[] = {"Try a safe link", "Try a tricky link", "Try a dangerous link"};
} // namespace

LinkTab::LinkTab(int x, int y, int w, int h, SecurityManager& manager)
    : TabPage(x, y, w, h, "Link Checker",
              "Paste a link BEFORE you click it. We will tell you if it is safe.", manager) {
    linkInput = new Fl_Input(x, y + 26, w - 170, 42, "Paste the link here:");
    linkInput->align(FL_ALIGN_TOP_LEFT);
    linkInput->tooltip("For example: https://www.wikipedia.org");

    auto* checkBtn = new FlatButton(x + w - 156, y + 26, 156, 42, "Check it!");
    theme::button(checkBtn, theme::blue);
    checkBtn->labelsize(15);
    ON_CLICK(LinkTab, checkBtn, onCheck);

    auto* tryLabel = new Fl_Box(x, y + 80, 60, 30, "Or try:");
    theme::hint(tryLabel);
    tryLabel->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    for (int i = 0; i < 3; ++i) {
        auto* example = new FlatButton(x + 60 + i * 190, y + 80, 180, 30, kExampleNames[i]);
        theme::button(example, theme::slate);
        exampleButtons[i] = example;
        example->callback([](Fl_Widget* clicked, void* d) {
            auto* self = static_cast<LinkTab*>(d);
            for (int k = 0; k < 3; ++k) // which example button was clicked?
                if (self->exampleButtons[k] == clicked)
                    self->fillExample(k);
        }, this);
    }

    banner = new StatusBanner(x, y + 130, w, 86);
    banner->set("Waiting for a link...", "Paste a link above and press Check it!", theme::muted);

    reasons = new Console(x, y + 246, w, h - 246 - 86, "Why did we say that?", theme::text);
    reasons->println("The reasons will show up here.");

    advice = new Fl_Box(x, y + h - 76, w, 70, "");
    advice->box(FL_RFLAT_BOX);
    advice->color(theme::card);
    advice->labelcolor(theme::text);
    advice->labelsize(14);
    advice->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);

    end();
}

void LinkTab::fillExample(int index) {
    linkInput->value(kExamples[index]);
    onCheck();
}

void LinkTab::onCheck() {
    guarded([this] {
        LinkReport report = manager.checkLink(linkInput->value());
        std::string verdict = report.verdict();

        if (verdict == "Safe") {
            banner->set("SAFE - this link looks fine",
                        "Website: " + report.host + "   |   Danger points: " +
                            std::to_string(report.score) + " (0-1 is safe)",
                        theme::slotColor(theme::SlotLow));
            advice->copy_label("  What should I do?  You can open it. Still, only click links from people you know.");
        } else if (verdict == "Suspicious") {
            banner->set("BE CAREFUL - something looks odd",
                        "Website: " + report.host + "   |   Danger points: " +
                            std::to_string(report.score) + " (2-3 is suspicious)",
                        theme::slotColor(theme::SlotMedium));
            advice->copy_label("  What should I do?  Do not type any password on it. Ask a grown-up before you open it.");
        } else {
            banner->set("DANGEROUS - do not click it!",
                        "Website: " + report.host + "   |   Danger points: " +
                            std::to_string(report.score) + " (4 or more is dangerous). A problem was added to the Problems page.",
                        theme::slotColor(theme::SlotCritical));
            advice->copy_label("  What should I do?  Do not click it. Delete the message and tell a grown-up or the security team.");
        }
        advice->redraw();

        reasons->clear();
        for (const std::string& reason : report.reasons)
            reasons->println("  *  " + reason);
    });
}
