from django import forms
from app_kamerka.models import Watchlist

class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField()
#
class CoordinatesForm(forms.Form):
    coordinates = forms.CharField(max_length=100)

class CountryForm(forms.Form):
    country = forms.CharField(max_length=100)
    all = forms.BooleanField(required=False)

class CountryHealthcareForm(forms.Form):
    country_healthcare = forms.CharField(max_length=100)
    all = forms.BooleanField(required=False)

class InfraForm(forms.Form):
    country_infra = forms.CharField(max_length=100)
    all = forms.BooleanField(required=False)

class DevicesNearbyForm(forms.Form):
    id = forms.CharField(max_length=100)


class WatchlistForm(forms.ModelForm):
    query_items_text = forms.CharField(
        required=False,
        help_text="Comma-separated query keys, e.g. niagara,modbus,bacnet",
    )

    class Meta:
        model = Watchlist
        fields = [
            "name",
            "query_type",
            "country",
            "coordinates",
            "category",
            "healthcare",
            "all_results",
            "enabled",
            "refresh_interval_minutes",
        ]

    def clean_query_items_text(self):
        raw = self.cleaned_data.get("query_items_text", "") or ""
        return [item.strip() for item in raw.split(",") if item.strip()]
