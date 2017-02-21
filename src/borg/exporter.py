import json


def export_data(data, path):
    """ Method to export data to a specific path
    """
    with open(path, 'w') as output:
        json.dump(data, output)
