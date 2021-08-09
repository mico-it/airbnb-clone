import datetime
from django import template
from reservations import models as reservation_models

register = template.Library()


@register.simple_tag
def is_booked(room, day):
    if day.number == 0:
        return False
    try:
        day_to_find = datetime.datetime(year=day.year, month=day.month, day=day.number)
        reservation_models.BookedDay.objects.get(
            reservation__room=room, day=day_to_find
        )
        return True
    except reservation_models.BookedDay.DoesNotExist:
        return False
