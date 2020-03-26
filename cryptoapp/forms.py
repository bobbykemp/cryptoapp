from django import forms

class HashForm(forms.Form):
    value_to_hash = forms.CharField()

class RSAForm(forms.Form):
    pass