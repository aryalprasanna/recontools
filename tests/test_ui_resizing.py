import pytest
from textual.app import App
from ui.dashboard import ReconDashboard


@pytest.mark.asyncio
async def test_extreme_resizing_does_not_crash():
    """Test that resizing the app down to extremely small grids does not crash."""
    
    # We pass mock options needed by __init__
    options = {
        "dns": False, "ip_intel": False, "ports": False,
        "ssl": False, "whois": False, "subdomains": False,
        "headers": False, "fingerprint": False, "export": False
    }
    
    app = ReconDashboard(target="example.com", options=options)
    
    async with app.run_test(size=(1, 1)) as pilot:
        await pilot.pause()
        assert app._exception is None, "App crashed on 1x1 resize"
    
    # Textual requires a fresh test session for totally new terminal sizes in testing
    app2 = ReconDashboard(target="example.com", options=options)
    async with app2.run_test(size=(10, 5)) as pilot:
        await pilot.pause()
        assert app2._exception is None, "App crashed on 10x5 resize"
        
        monitor = app2.query_one("#process-monitor")
        assert monitor is not None
