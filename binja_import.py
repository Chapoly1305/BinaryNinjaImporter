#!/usr/bin/env python3
"""
Binary Ninja IDA Import Script
Imports function names and comments from IDA Pro JSON export
"""

import json
import binaryninja
from binaryninja.interaction import OpenFileNameField, get_form_input, ChoiceField
from binaryninja.plugin import PluginCommand


def import_ida_data(bv, json_file_path, import_functions=True, import_comments=True, verbose=True):
    """
    Import IDA Pro analysis data into Binary Ninja
    
    Args:
        bv: Binary Ninja BinaryView object
        json_file_path: Path to the JSON file exported from IDA Pro
        import_functions: Whether to import function names
        import_comments: Whether to import comments
        verbose: Whether to print progress messages
    
    Returns:
        tuple: (success: bool, error_message: str or None)
    """
    
    def log(message):
        if verbose:
            print(message)
    
    try:
        # Load the JSON data
        log("Loading JSON file: {}".format(json_file_path))
        with open(json_file_path, 'r', encoding='utf-8') as f:
            ida_data = json.load(f)
        
        functions_data = ida_data.get("functions", {})
        names_data = ida_data.get("names", {})
        
        log("Found {} functions in IDA export".format(len(functions_data)))
        
        # Wait for analysis to complete
        log("Waiting for analysis to complete...")
        bv.update_analysis_and_wait()
        
        imported_functions = 0
        renamed_functions = 0
        imported_comments = 0
        
        # Process functions
        if import_functions:
            log("Importing function names...")
            
            for func_name, func_data in functions_data.items():
                func_addr = func_data.get("start")
                if func_addr is None:
                    continue
                
                # Skip if function name starts with "sub_" (auto-generated)
                if func_name.startswith("sub_"):
                    continue
                
                # Create function if it doesn't exist
                existing_func = bv.get_function_at(func_addr)
                if existing_func is None:
                    log("Creating function at 0x{:x}".format(func_addr))
                    bv.add_function(func_addr)
                    bv.update_analysis_and_wait()
                    existing_func = bv.get_function_at(func_addr)
                    imported_functions += 1
                
                if existing_func is not None:
                    # Rename function if name is different and meaningful
                    current_name = existing_func.name
                    if current_name != func_name and not func_name.startswith("sub_"):
                        log("Renaming function 0x{:x}: {} -> {}".format(func_addr, current_name, func_name))
                        existing_func.name = func_name
                        renamed_functions += 1
                    
                    # Import function comment
                    if import_comments and "comment" in func_data and func_data["comment"]:
                        comment = func_data["comment"]
                        if comment.strip():
                            log("Setting function comment for {}: {}".format(func_name, comment[:50] + "..." if len(comment) > 50 else comment))
                            existing_func.comment = comment
                            imported_comments += 1
                    
                    # Import line comments within the function
                    if import_comments and "comments" in func_data:
                        for addr_str, comment in func_data["comments"].items():
                            try:
                                addr = int(addr_str)
                                if comment and comment.strip():
                                    log("Setting line comment at 0x{:x}: {}".format(addr, comment[:30] + "..." if len(comment) > 30 else comment))
                                    existing_func.set_comment_at(addr, comment)
                                    imported_comments += 1
                            except (ValueError, TypeError) as e:
                                log("Warning: Could not parse address {}: {}".format(addr_str, e))
                                continue
        
        # Import standalone symbols/names
        log("Importing symbol names...")
        imported_symbols = 0
        
        for addr_str, name in names_data.items():
            try:
                addr = int(addr_str)
                if name and not name.startswith("sub_"):
                    # Check if there's already a function at this address
                    existing_func = bv.get_function_at(addr)
                    if existing_func is None:
                        # Create a symbol
                        from binaryninja.types import Symbol
                        from binaryninja.enums import SymbolType
                        symbol = Symbol(SymbolType.FunctionSymbol, addr, name)
                        bv.define_user_symbol(symbol)
                        imported_symbols += 1
                        log("Created symbol at 0x{:x}: {}".format(addr, name))
            except (ValueError, TypeError):
                continue
        
        # Final analysis update
        log("Updating analysis...")
        bv.update_analysis_and_wait()
        
        # Summary
        log("\n=== Import Summary ===")
        log("Functions created: {}".format(imported_functions))
        log("Functions renamed: {}".format(renamed_functions))
        log("Comments imported: {}".format(imported_comments))
        log("Symbols created: {}".format(imported_symbols))
        log("Import completed successfully!")
        
        return True, None
        
    except FileNotFoundError:
        return False, "JSON file not found: {}".format(json_file_path)
    except json.JSONDecodeError as e:
        return False, "Invalid JSON file: {}".format(str(e))
    except Exception as e:
        return False, "Import failed: {}".format(str(e))


def import_ida_interactive():
    """Interactive import with GUI dialogs"""
    # Get current binary view
    bv = binaryninja.current_view
    if bv is None:
        print("No binary is currently open. Please open a binary file first.")
        return
    
    # Get import options through GUI
    json_file_field = OpenFileNameField("Select IDA Export JSON file", "*.json")
    import_functions_choice = ChoiceField("Import Function Names", ["Yes", "No"])
    import_comments_choice = ChoiceField("Import Comments", ["Yes", "No"])
    
    if not get_form_input([json_file_field, import_functions_choice, import_comments_choice], 
                         "IDA Import Options"):
        print("Import cancelled")
        return
    
    if not json_file_field.result:
        print("No JSON file selected")
        return
    
    # Run the import
    success, error_msg = import_ida_data(
        bv=bv,
        json_file_path=json_file_field.result,
        import_functions=import_functions_choice.result == 0,
        import_comments=import_comments_choice.result == 0,
        verbose=True
    )
    
    if not success:
        print("Import failed: {}".format(error_msg))


def import_ida_script_mode():
    """Script mode with file dialogs"""
    # Get JSON file and binary file through GUI
    json_file_field = OpenFileNameField("Select IDA Export JSON file", "*.json")
    binary_file_field = OpenFileNameField("Select Binary file to import into")
    import_functions_choice = ChoiceField("Import Function Names", ["Yes", "No"])
    import_comments_choice = ChoiceField("Import Comments", ["Yes", "No"])
    
    if not get_form_input([json_file_field, binary_file_field, import_functions_choice, import_comments_choice], 
                         "IDA Import Options"):
        print("Import cancelled")
        return
    
    if not json_file_field.result or not binary_file_field.result:
        print("Both JSON file and binary file must be selected")
        return
    
    # Load the binary using Binary Ninja v5.0 API
    try:
        print("Loading binary: {}".format(binary_file_field.result))
        bv = binaryninja.load(binary_file_field.result, update_analysis=True)
        
        if bv is None:
            print("Could not load binary file")
            return
            
        print("Binary loaded successfully")
        print("Architecture: {}".format(bv.arch.name if bv.arch else "Unknown"))
        print("Platform: {}".format(bv.platform.name if bv.platform else "Unknown"))
        
    except Exception as e:
        print("Error loading binary: {}".format(e))
        return
    
    # Run the import
    success, error_msg = import_ida_data(
        bv=bv,
        json_file_path=json_file_field.result,
        import_functions=import_functions_choice.result == 0,
        import_comments=import_comments_choice.result == 0,
        verbose=True
    )
    
    if success:
        # Save the database if it was loaded from a raw binary
        if not binary_file_field.result.endswith('.bndb'):
            bndb_path = binary_file_field.result + '.bndb'
            print("Saving analysis to: {}".format(bndb_path))
            bv.create_database(bndb_path)
    else:
        print("Import failed: {}".format(error_msg))


# Register as plugin command
if __name__ == "__main__":
    # When run as script, use script mode
    import_ida_script_mode()
else:
    # Register as plugin command
    PluginCommand.register(
        "Import IDA Analysis Data", 
        "Import function names and comments from IDA Pro JSON export",
        import_ida_interactive
    )
