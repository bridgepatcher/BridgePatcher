"""
model_array.py: Datasets for different models
"""


SupportedSMBIOS = [
    "MacBookAir8,1",
    "MacBookAir8,2",
    "MacBookAir9,1",
    # MacBook Pro
    "MacBookPro15,1",
    "MacBookPro15,2",
    "MacBookPro15,3",
    "MacBookPro15,4",
    # "MacBookPro16,1"
    # "MacBookPro16,2"
    "MacBookPro16,3",
    # Mac Mini
    "Macmini8,1",
    # iMac Pro
    "iMacPro1,1",
    # "VMWare20,1" # nur zum Testen der Syntax von der App, damit das erleichtert wird, weil ich habe keinen Mac, auf denen ich direkt Root Patches einspielen kann, nur der Syntax zu testen
]

# Macs with Apple T2 Security Chip (used for OpenCore build / patch routing)
T2Macs = [
    "MacBookAir8,1",
    "MacBookAir8,2",
    "MacBookAir9,1",
    "MacBookPro15,1",
    "MacBookPro15,2",
    "MacBookPro15,3",
    "MacBookPro15,4",
    "MacBookPro16,1",
    "MacBookPro16,2",
    "MacBookPro16,3",
    "MacBookPro16,4",
    "MacPro7,1",
    "Macmini8,1",
    "iMac20,1",
    "iMac20,2",
    "iMacPro1,1",
]