"""Web Screenshot module to fetch title and meta descriptions."""

import asyncio
import httpx
from bs4 import BeautifulSoup
from typing import Optional

from core.dataclasses import ScreenshotData


class WebScreenshotModule:
    """Module to grab HTML text content 'screenshot' using BeautifulSoup."""

    @staticmethod
    async def capture(url: str) -> Optional[ScreenshotData]:
        """Asynchronously fetch the target and extract title and description."""
        if not url.startswith('http'):
            url = f'http://{url}'
            
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                response = await client.get(url, follow_redirects=True)
                
                if response.status_code != 200:
                    return None
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract title
                title_tag = soup.title
                title = title_tag.string.strip() if title_tag and title_tag.string else "No Title Found"
                
                # Extract meta description
                meta_desc_tag = soup.find('meta', attrs={'name': 'description'})
                description = None
                if meta_desc_tag and meta_desc_tag.get('content'):
                    description = meta_desc_tag['content'].strip()
                
                raw_text = soup.get_text(separator=' ', strip=True)[:500] + '...' 
                
                return ScreenshotData(
                    title=title,
                    description=description,
                    raw_text=raw_text
                )
        except Exception as e:
            # Handle timeout, connection error, etc.
            return None
