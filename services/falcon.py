from __future__ import annotations

from falconpy import NGSIEM, RealTimeResponse, RealTimeResponseAdmin

from config import Settings


class FalconClients:
    def __init__(self, settings: Settings) -> None:
        common_args: dict[str, str] = {
            "client_id": settings.client_id,
            "client_secret": settings.client_secret,
        }
        if settings.base_url:
            common_args["base_url"] = settings.base_url

        self.ngsiem = NGSIEM(**common_args)
        self.rtr = RealTimeResponse(**common_args)
        self.rtr_admin = RealTimeResponseAdmin(**common_args)
