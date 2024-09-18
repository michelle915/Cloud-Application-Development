from google.cloud import datastore
from flask import Flask, request, jsonify, make_response
import json
import constants
import re

app = Flask(__name__)
client = datastore.Client()

@app.route('/')
def index():
    return "Assignment 5: Advanced REST Features"

def validate_attributes(content):
    errors = {}

    # Validate name length
    if 'name' in content and len(content['name']) > 20:
        errors['name'] = "Name cannot be longer than 20 characters."

    # Validate type for no special characters (only allow alphanumeric and spaces)
    if 'type' in content and not re.match(r'^[\w ]+$', content['type']):
        errors['type'] = "Type cannot contain special characters."

    return errors

# Boolean unique name function
def unique_name(name, exclude_id=None):
    query = client.query(kind=constants.boats)
    results = list(query.fetch())
    print(results)
    for boat in results:
        if boat['name'] == name and str(boat.key.id) != str(exclude_id):
            print(boat['name'])
            print(name)
            return False
    print(f"Name {name} is unique.")        
    return True

# Routes for all boats
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():

    # POST
    if request.method == 'POST':
        # Invalidate requests with Accept MIME types that are not supported
        if request.headers.get('Accept') != 'application/json':
            response = {"Error": "Accept MIME type not supported"}
            return jsonify(response), 406

        # Invalidate request when client sends an unsupported MIME type to the endpoint
        if request.content_type != 'application/json':
            response = {"Error": "Request must be JSON"}
            return jsonify(response), 415

        content = request.get_json()
        
        # Check for all required attributes
        required_attributes = ["name", "type", "length"]
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        # Invalidate inputs that have keys other than "name", "type", or "length"
        if not all(key in required_attributes for key in content.keys()):
            response = {"Error": "The request object contains unsupported attributes"}
            return jsonify(response), 400

        # Validate attributes
        validation_errors = validate_attributes(content)
        if validation_errors:
            return jsonify({"Error": validation_errors}), 400

        # Ensure unique name
        if not unique_name(content["name"]):
            response = {"Error": "Boat name must be unique"}
            return jsonify(response), 403    

        # Create and store new boat
        new_boat = datastore.Entity(key=client.key(constants.boats))
        new_boat.update({
            "name": content["name"],
            "type": content["type"],
            "length": content["length"],
        })
        client.put(new_boat)

        # Update the boat's id attribute 
        new_boat["id"] = new_boat.key.id
        client.put(new_boat)
        
        # Return created boat, along with a generated self-link
        response = {
            "id": new_boat["id"],
            "name": new_boat["name"],
            "type": new_boat["type"],
            "length": new_boat["length"],
            "self": f"{request.url_root}boats/{new_boat['id']}"
        }
        return jsonify(response), 201
    
    # GET
    elif request.method == 'GET':
        # Invalidate requests with Accept MIME types that are not supported
        if request.headers.get('Accept') != 'application/json':
            response = {"Error": "Accept MIME type not supported"}
            return jsonify(response), 406
        
        # Pagination setup for boats
        limit = 3
        query = client.query(kind=constants.boats)
        total_results = list(query.fetch())
        offset = request.args.get('offset', 0, int)
        query = client.query(kind=constants.boats)
        query_iter = query.fetch(limit=limit, offset=offset)
        results = list(query_iter)
        
        # Aggregate information for all boats
        boats = []

        for boat in results:

            # Generate self information
            a_boat = {
                "id": boat["id"],
                "name": boat["name"],
                "type": boat["type"],
                "length": boat["length"],
                "self": f"{request.url_root}boats/{boat['id']}"
            }
            boats.append(a_boat)
        
        output = {
            "boats": boats
        }

        # Add a "next" link if more boats are available
        if len(total_results) > offset + limit:
            output["next"] = f"{request.url_root}boats?offset={offset + limit}"

        return jsonify(output), 200
    
    # UNKNOWN ROUTE
    else:
        return '', 405

# Routes for a boat
@app.route('/boats/<id>', methods=['DELETE','GET', 'PUT', 'PATCH'])
def boat_delete_get_edit(id):
    boat_key = client.key(constants.boats, int(id))
    boat = client.get(key=boat_key)
    
    # GET
    if request.method == 'GET':
        # Invalidate requests with Accept header set to a MIME type that is not supported
        if request.headers.get('Accept') != 'text/html' and request.headers.get('Accept') != 'application/json':
            response = {"Error": "Accept MIME type not supported"}
            return jsonify(response), 406

        # Boat ID not found
        if not boat:
            response = {"Error": "No boat with this boat_id exists"}
            return jsonify(response), 404

        # Generate self information
        response = {
            "id": boat["id"],
            "name": boat["name"],
            "type": boat["type"],
            "length": boat["length"],
            "self": f"{request.url_root}boats/{boat['id']}"
        }

        # Return HTML
        if request.headers.get('Accept') == 'text/html':
            response_html = "<ul>"
            for key, value in response.items():
                response_html += f"<li>{key}: {value}</li>"
            response_html += "</ul>"
            return response_html, 200, {'Content-Type': 'text/html'}
        
        # Return JSON
        return jsonify(response), 200

    # Boat ID not found
    if not boat:
        response = {"Error": "No boat with this boat_id exists"}
        return jsonify(response), 404

    # Invalidate requests with Accept header set to a MIME type that is not supported
    elif request.headers.get('Accept') != 'application/json':
        response = {"Error": "Accept MIME type not supported"}
        return jsonify(response), 406

    # DELETE    
    elif request.method == 'DELETE':
        client.delete(boat_key)
        return '', 204

    # Invalidate EDIT request when client sends an unsupported MIME type to the endpoint
    if request.content_type != 'application/json':
        response = {"Error": "Request must be JSON"}
        return jsonify(response), 415

    content = request.get_json()

    # Forbid ID edit
    if 'id' in content:
        response = {"Error": "Updating the value of id is not allowed"}
        return jsonify(response), 403

    # Invalidate inputs that have keys other than "name", "type", or "length"
    required_attributes = ["name", "type", "length"]
    if not all(key in required_attributes for key in content.keys()):
        response = {"Error": "The request object contains unsupported attributes"}
        return jsonify(response), 400

    # Validate attributes
    validation_errors = validate_attributes(content)
    if validation_errors:
        return jsonify({"Error": validation_errors}), 400

    # If name edit requested, check for unique name
    if 'name' in content and not unique_name(content["name"], id):
        response = {"Error": "Boat name must be unique"}
        return jsonify(response), 403

    # PUT
    if request.method == 'PUT':
        # Check for all required attributes
        if not all(attr in content for attr in required_attributes):
            response = {"Error": "The request object is missing at least one of the required attributes"}
            return jsonify(response), 400

        print(boat)
        boat.update(content)
        print(boat)

        client.put(boat)

        # Respond with 303 See Other
        response = make_response('', 303)
        response.headers["Location"] = f"{request.url_root}boats/{boat.key.id}"
        return response

    # PATCH
    elif request.method == 'PATCH':
        print(boat)
        boat.update(content)
        print(boat)
        client.put(boat)
        return jsonify(boat), 200

    # UNKNOWN ROUTE
    else:
        return 'Method not recognized'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)