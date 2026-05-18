from streamlit.testing.v1 import AppTest


def test_navigation_from_attack_sets_to_history_changes_on_first_click():
    app = AppTest.from_file("ui/streamlit_app.py")
    app.run(timeout=10)

    app.segmented_control[0].set_value("Attack Sets").run(timeout=10)
    assert app.session_state["page"] == "Attack Sets"

    app.segmented_control[0].set_value("History").run(timeout=10)
    assert app.session_state["page"] == "History"
    assert not app.exception


def test_run_page_does_not_render_llm_judge_checkbox():
    app = AppTest.from_file("ui/streamlit_app.py")
    app.run(timeout=10)

    labels = [checkbox.label for checkbox in app.checkbox]
    assert "Use LLM judge for response analysis (paid)" not in labels
    assert not app.exception
