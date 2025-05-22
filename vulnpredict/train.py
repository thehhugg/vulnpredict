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
    features = df.drop(columns=['label'])
    labels = df['label']
    train_model(features, labels)

if __name__ == '__main__':
    main() 