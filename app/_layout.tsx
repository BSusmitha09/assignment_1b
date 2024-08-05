import React, { useState } from 'react';
import { View, Text, TextInput, Button, ScrollView, Pressable, LayoutAnimation, Platform, UIManager, Alert } from 'react-native';

if (Platform.OS === 'android') {
  if (UIManager.setLayoutAnimationEnabledExperimental) {
    UIManager.setLayoutAnimationEnabledExperimental(true);
  }
}

export default function Layout() {
  const [todos, setTodos] = useState([]);
  const [form, setForm] = useState({title: "", description: ""});

  const todoStyle = {
    backgroundColor: "#FFF",
    padding: 16,
    borderWidth: 1,
    borderRadius: 16,
    marginBottom: 16,
  };

  const todoDescriptionStyle = {
    marginTop: 8,
    marginBottom: 8,
    paddingTop: 8,
    borderTopColor: "#000",
    borderTopWidth: 1,
  };

  const toggleCollapse = (index:number) => {
    LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
    setTodos(prev => {
      const newTodos = [...prev];
      newTodos[index].is_collapsed = !newTodos[index].is_collapsed;
      return newTodos;
    });
  };

  const deleteTodo = (index:number) => {
    LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
    setTodos(prev => {
      const newTodos = [...prev];
      newTodos.splice(index, 1);
      return newTodos;
    });
  };

  return (
    <View style={{ 
      backgroundColor: "#000",
      flex: 1,
      paddingTop: 40,
    }}>
      <Text style={{
        color: "#FFF",
        fontSize: 24,
        textAlign: "center",
        padding: 16,
        fontWeight: "bold",
      }}>Todo Application</Text>
      <View style={{
        backgroundColor: "#FFF",
        borderTopLeftRadius: 16,
        borderTopRightRadius: 16,
        padding: 16,
      }}>
        <TextInput
          style={{
            height: 40,
            borderColor: 'gray',
            borderWidth: 1,
            marginBottom: 8,
            padding: 8,
            borderRadius: 8,
          }}
          placeholder="Title"
		  value={form.title}
      	  onChange={(event) => setForm({...form, title: event.nativeEvent.text})}
        />
        <TextInput
          style={{
            height: 40,
            borderColor: 'gray',
            borderWidth: 1,
            marginBottom: 8,
            padding: 8,
            borderRadius: 8,
          }}
          placeholder="Description"
		  value={form.description}
		  onChange={(event) => setForm({...form, description: event.nativeEvent.text})}
        />
        <Button
          title="Add Todo"
          color="#000"
		  onPress={() => {
			LayoutAnimation.configureNext(LayoutAnimation.Presets.easeInEaseOut);
			setTodos(prev => {
			  if (!form.title || !form.description) {
				Alert.alert("Please fill all fields");
				return prev;
			  }
			  return [...prev, {
				title: form.title,
				description: form.description,
				is_collapsed: true,
			  }];
			});
			if (!form.title || !form.description) {
			  return;
			}
			setForm({title: "", description: ""});
		  }}
        />
      </View>
      <ScrollView style={{
        flex: 1,
        backgroundColor: "#FFF",
        borderBottomLeftRadius: 16,
        borderBottomRightRadius: 16,
        padding: 16,
      }}>
        {todos.length!=0 && todos.map((todo, index) => (
          <View key={index} style={todoStyle}>
            <View style={{
              flexDirection: "row",
              justifyContent: "space-between",
              alignContent: "center",
            }}>
              <Text>{todo.title}</Text>
              <Pressable onPress={() => toggleCollapse(index)}>
                <Text>{todo.is_collapsed ? "expand" : "collapse"}</Text>
              </Pressable>
            </View>
            {!todo.is_collapsed && (
              <View style={todoDescriptionStyle}>
                <Text>{todo.description}</Text>
                <Pressable onPress={() => deleteTodo(index)}>
                  <Text style={{
                    color: "#FF0000",
                    paddingTop: 8,
                  }}>delete</Text>
                </Pressable>
              </View>
            )}
          </View>
        )) || <Text style={{
		  color: "#000",
		  textAlign: "center",
		  padding: 16,
		}}>Your completed all Tasks</Text>}
      </ScrollView>
    </View>
  );
}