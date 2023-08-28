from swiftcrypt import DataMasking

data_masker = DataMasking()

original_text = "Hello55s98221__6Yooo"
masked_text = data_masker.mask_data(original_text, masking_character="#", chars_to_mask=9)
"""Replace the x amount of letters with the masking character."""

original_credit_card = "4012888888881881"
masked_credit_card = data_masker.credit_card_mask(original_credit_card,"*")

"""This here is used for credit cards, it returns the last 3 digits."""
print(masked_credit_card,masked_text)