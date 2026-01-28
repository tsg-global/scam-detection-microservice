import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from app.config import settings

logger = logging.getLogger(__name__)


class PortalAPIClient:
    """Client for interacting with the TSG Global Admin Portal API"""

    def __init__(self):
        self.base_url = settings.portal_api_url
        self.api_key = settings.portal_api_key
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def get_outbound_messages(
        self,
        start_datetime: str,
        end_datetime: str,
        page: int = 1,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Fetch outbound SMS messages from the portal API

        Args:
            start_datetime: ISO format datetime string
            end_datetime: ISO format datetime string
            page: Page number (default 1)
            limit: Results per page (default 100)

        Returns:
            List of message dictionaries
        """
        try:
            async with httpx.AsyncClient() as client:
                params = {
                    "page": page,
                    "limit": limit,
                    "filter[type]": "outbound",
                    "filter[start-inserted_at]": start_datetime,
                    "filter[end-inserted_at]": end_datetime,
                    "sort": "-inserted_at",
                }

                response = await client.get(
                    f"{self.base_url}/smses",
                    headers=self.headers,
                    params=params,
                    timeout=30.0,
                )
                response.raise_for_status()

                messages = response.json()
                logger.info(
                    f"Fetched {len(messages)} messages from portal API "
                    f"(page {page}, {start_datetime} to {end_datetime})"
                )
                return messages

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch messages from portal API: {e}")
            raise

    async def get_all_messages_in_range(
        self, start_datetime: str, end_datetime: str
    ) -> List[Dict[str, Any]]:
        """
        Fetch all messages in a time range (handles pagination)

        Args:
            start_datetime: ISO format datetime string
            end_datetime: ISO format datetime string

        Returns:
            List of all message dictionaries
        """
        all_messages = []
        page = 1
        limit = 100

        while True:
            messages = await self.get_outbound_messages(
                start_datetime=start_datetime,
                end_datetime=end_datetime,
                page=page,
                limit=limit,
            )

            if not messages:
                break

            all_messages.extend(messages)

            if len(messages) < limit:
                break

            page += 1

        logger.info(
            f"Fetched total of {len(all_messages)} messages from "
            f"{start_datetime} to {end_datetime}"
        )
        return all_messages
