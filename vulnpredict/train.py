import pandas as pd
from .ml import train_model
import click

@click.command()
@click.argument('csv_file')
def main(csv_file):
    """
    Train the VulnPredict model from a labeled CSV file.
    """
    df = pd.read_csv(csv_file)
    raw_features = df.drop(columns=['label'])
    labels = df['label']
    from .ml import extract_features
    features = extract_features(raw_features.to_dict(orient='records'))
    train_model(features, labels)

if __name__ == '__main__':
    main() 
