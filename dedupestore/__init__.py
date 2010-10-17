# This is a python package

ARCHIVE_SCHEMA = """
{
    "name": "Archive",
    "type": "record",
    "fields" : [
        { "name": "name", "type": "string" },
        { "name": "ts",   "type": "string" },
        { "name": "chunks", "type": { "type": "array", "items":
            { "type": "record",
              "name": "Chunk",
              "fields": [
                { "name": "id", "type": {"type": "fixed", "size": 32, "name": "sha256" }},
                { "name": "size", "type": "int" }
              ]
            }
        }},
        { "name": "items", "type": {"type": "array", "items":
            {
                "type": "record",
                "name": "Item",
                "fields": [
                    { "name": "type", "type":
                      { "name": "ItemType", "type": "enum", "symbols": ["FILE", "DIRECTORY"] } },
                    { "name": "path", "type": "string" },
                    { "name": "size", "type": ["null", "long"] },
                    { "name": "chunks", "type": ["null",
                        { "type": "array", "items": "int" }
                    ]}
                ]
            }
        }}
    ]
}
"""
from avro import schema
archive_schema = schema.parse(ARCHIVE_SCHEMA)
