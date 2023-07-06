# -*- coding: utf-8 -*-
# Time       : 2023/7/7 3:24
# Author     : QIN2DIM
# Github     : https://github.com/QIN2DIM
# Description:
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from os.path import dirname
from pathlib import Path
from typing import Literal

from loguru import logger

__all__ = ["project", "init_log"]


@dataclass
class Project:
    src_point = Path(dirname(__file__))
    root_point = src_point
    database = root_point.joinpath("database")

    logs = root_point.joinpath("logs")

    def __post_init__(self):
        os.makedirs(self.database, exist_ok=True)


def init_log(*, stdout_level: Literal["INFO", "DEBUG"] = "DEBUG", **sink_channel):
    event_logger_format = "<g>{time:YYYY-MM-DD HH:mm:ss}</g> | <lvl>{level}</lvl> - {message}"
    serialize_format = event_logger_format + "- {extra}"
    logger.remove()
    logger.add(
        sink=sys.stdout, colorize=True, level=stdout_level, format=serialize_format, diagnose=False
    )
    if sink_channel.get("error"):
        logger.add(
            sink=sink_channel.get("error"),
            level="ERROR",
            rotation="1 week",
            encoding="utf8",
            diagnose=False,
            format=serialize_format,
        )
    if sink_channel.get("runtime"):
        logger.add(
            sink=sink_channel.get("runtime"),
            level="DEBUG",
            rotation="20 MB",
            retention="20 days",
            encoding="utf8",
            diagnose=False,
            format=serialize_format,
        )
    if sink_channel.get("serialize"):
        logger.add(
            sink=sink_channel.get("serialize"),
            level="DEBUG",
            format=serialize_format,
            encoding="utf8",
            diagnose=False,
            serialize=True,
        )
    return logger


project = Project()
init_log(
    error=project.logs.joinpath("error.log"),
    runtime=project.logs.joinpath("runtime.log"),
    serialize=project.logs.joinpath("serialize.log"),
)
