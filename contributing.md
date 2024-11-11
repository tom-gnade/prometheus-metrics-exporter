# Contributing Guidelines

This document defines the core development guidelines and standards for the Prometheus Metrics Exporter project. All contributions must follow these directives.

## Change Management Process

1. Change Proposal Analysis
   - Summarize proposed changes before implementation
   - Document alignment with code goals
   - Verify consistency with existing code
   - Explain benefits and impacts
   - Include risk assessment for proposed changes
   - Identify affected components and dependencies

2. Goal Alignment
   - Review code goals in file headers
   - Ensure changes support stated purpose 
   - Maintain code organization
   - Document any goal deviations
   - Verify alignment with architectural principles
   - Consider impact on existing features

3. Implementation Approach
   - Use simplest viable implementation
   - Verify alignment with goals
   - Maintain code organization
   - Avoid unnecessary complexity
   - Document implementation choices
   - Include performance considerations
   - Consider maintenance implications

4. Reliability and Error Handling
   - Prioritize error conditions
   - Implement robust error handling
   - Maintain reliability measures
   - Document error scenarios
   - Verify error coverage
   - Include logging strategy
   - Define recovery procedures

## Coding Standards

1. Indentation
   - 4 spaces per level
   - No tabs, only spaces
   - Configure editor appropriately
   - Maintain consistency
   - Use automated formatting tools

2. Code Segmentation
   ```python
   #-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
   # Section Name - Brief description of purpose
   #-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~-+-~
   ```
   - Use for major code segments
   - Maintain 79 character length
   - Center section names
   - Add brief section purpose comment

3. Change Management
   - Present changes in discrete blocks
   - Group by major sections
   - Include clear merge instructions
   - Maintain section context
   - Add change validation steps
   - Include rollback procedures

4. Structural Organization

   Your code should follow this organizational structure:

   ```
   1. Imports and System Configuration
      - Standard library imports
      - Third-party imports
      - Local imports
      - System configurations

   2. Base Definitions
      - Exceptions
      - Enums
      - Constants
      - Data classes
      - Type definitions

   3. Configuration Classes
      - Settings
      - Environment configs
      - Feature flags

   4. Core Implementations
      - Utility classes
      - Service classes
      - Manager classes
      - Main application classes

   5. Program Entry
      - Main function
      - Entry point guard
   ```

5. Documentation Standards

   Complex classes and functions require detailed documentation:
   ```python
   class ComplexClass:
       """
       Brief class description.
       
       Detailed description of functionality, purpose,
       and implementation notes.
       
       Attributes:
           attr1 (type): Description
           attr2 (type): Description
           
       Note:
           Important usage or implementation notes
           
       Version:
           1.0: Initial implementation
           1.1: Added feature X
       """
   ```

   Simple classes and functions can use concise documentation:
   ```python
   class SimpleClass:
       """Handles basic data transformation with no side effects."""
   ```

   Documentation Requirements:
   - Clear purpose statement
   - Type hints
   - Grammatically correct
   - Professional tone
   - Avoid redundancy
   - Include version history
   - Add usage examples for complex features

   Style Rules:
   - Use triple double-quotes for all docstrings
   - Keep lines under 80 characters
   - End documentation with period
   - Use active voice
   - Be concise and clear
   - Include return value documentation
   - Document exceptions raised

## Pull Request Process

1. Ensure all changes follow these guidelines
2. Update documentation as needed
3. Add appropriate tests
4. Update version history
5. Submit for review

## Questions or Suggestions

If you have questions about these guidelines or suggestions for improvements, please open an issue for discussion.