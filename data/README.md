# Data Directory

## Dataset: PhiUSIIL Phishing URL Dataset

**Source:** [UCI Machine Learning Repository — PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)

**Citation:**
> Prasad, A., & Chandra, S. (2023). PhiUSIIL Phishing URL (Website) Dataset [Dataset]. UCI Machine Learning Repository. https://doi.org/10.24432/C59S6B

### Download Instructions

1. Visit the dataset page: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
2. Click the **Download** button to download the ZIP archive.
3. Extract the ZIP file.
4. Locate the main CSV file (usually named `PhiUSIIL_Phishing_URL_Dataset.csv` or similar).
5. Place the CSV file in **this directory** (`data/`).
6. Rename it to `phishing_dataset.csv` if needed, **OR** update the `DATA_PATH` in `backend/config.py`.

### Expected File Location

```
data/
  phishing_dataset.csv    ← Place the downloaded CSV here
  README.md               ← This file
  .gitkeep
```

### Dataset Information

- **Records:** 235,795 URLs
- **Features:** 54 columns
- **Label Column:** `label` (1 = Legitimate, 0 = Phishing)
- **URL Column:** `url` (raw URL string)

### License

The dataset is made available under the [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) license.
You must attribute the original authors when using this dataset.

### Privacy Note

This directory should **not** be committed to version control (see `.gitignore`).
The dataset may contain URLs that resolve to malicious content — do not visit them.
