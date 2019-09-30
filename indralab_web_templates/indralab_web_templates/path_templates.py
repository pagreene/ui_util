import logging

from flask import Blueprint

path_temps = Blueprint('path_temps', __name__, template_folder='templates')

logger = logging.getLogger(__name__)
